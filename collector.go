package main

import (
	"bufio"
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/hashicorp/golang-lru"
	"golang.org/x/time/rate"
)

const (
	dnsCacheTTLDefault   = 5 * time.Minute
	defaultRenderWait    = 2 * time.Second
	defaultRenderTimeout = 10 * time.Second
	defaultConnTimeout   = 800 * time.Millisecond
)

var defaultWebPorts = []int{80, 443, 8000, 8080, 8443, 8888, 9000, 10000}

var cmsDB = []struct {
	Name     string
	Patterns []string
	Path     string
}{
	{"WordPress", []string{"/wp-content/", "/wp-includes/", "wp-json"}, "/"},
	{"Drupal", []string{"/sites/default/", "Drupal", "drupal"}, "/"},
	{"Joomla", []string{"/media/system/js/", "Joomla"}, "/"},
	{"ThinkPHP", []string{"/thinkphp/", "thinkphp"}, "/"},
	{"Discuz", []string{"discuz", "comiis_"}, "/"},
	{"Magento", []string{"/skin/frontend/", "Magento"}, "/"},
	{"Laravel", []string{"laravel_session", "XSRF-TOKEN"}, "/"},
}

type CollectResult struct {
	Subdomains  []string               `json:"subdomains"`
	Directories []DirResult            `json:"directories"`
	APIs        []string               `json:"apis"`
	AuthIssues  map[string][]AuthIssue `json:"auth_issues"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type DirResult struct {
	URL    string `json:"url"`
	Status int    `json:"status_code"`
	Length int    `json:"length"`
	Title  string `json:"title"`
	Hash   uint64 `json:"hash"`
	Depth  int    `json:"-"`
}

type AuthIssue struct {
	URL        string            `json:"url"`
	Type       string            `json:"type"`
	Detail     string            `json:"detail"`
	Confidence string            `json:"confidence"`
	Payload    map[string]string `json:"payload,omitempty"`
	PoC        string            `json:"poc"`
}

type NotFoundSignature struct {
	Status    int
	Length    int
	Title     string
	Hash      uint64
	Keywords  []string
	AvgLength int
}

type cachedResponse struct {
	status int
	body   []byte
	fp     uint64
	ts     time.Time
}

type dirQueueItem struct {
	baseURL string
	depth   int
}

type ScanMetrics struct {
	RequestsTotal  atomic.Int64
	RequestsFailed atomic.Int64
	BytesReceived  atomic.Int64
	StartTime      time.Time
}

type Collector struct {
	cfg         Config
	pm          *ProxyManager
	wafDetector *WAFDetector
	client      *http.Client
	log         *log.Logger

	limiter *rate.Limiter

	mu            sync.Mutex
	results       CollectResult
	seenDir       map[string]bool
	seenAPI       map[string]bool
	seenSub       map[string]bool
	notFound404   *NotFoundSignature
	respCache     *lru.Cache
	jsCache       *lru.Cache
	cookieJar     *lru.Cache
	previousScan  map[string]uint64
	verifiedCache map[string]bool

	rootURL string

	wildcardIPs  []net.IP
	wildcardBody string

	lowFingerprint uint64
	lowValid       bool

	ctx      context.Context
	cancel   context.CancelFunc

	consecutiveFails   int
	consecutiveFailsMu sync.Mutex
	penaltyWeight      int32

	cmsName string

	dnsCache   map[string]dnsCacheEntry
	dnsCacheMu sync.RWMutex

	metrics ScanMetrics

	honeypotChecked  bool
	honeypotDetected bool
}

type dnsCacheEntry struct {
	ips []net.IP
	ts  time.Time
}

func NewCollector(cfg Config, pm *ProxyManager, wafDetector *WAFDetector) *Collector {
	limiter := rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateLimit)
	respCache, _ := lru.New(2000)
	jsCache, _ := lru.New(500)
	cookieJar, _ := lru.New(100)

	var ctx context.Context
	var cancel context.CancelFunc
	if cfg.MaxScanDuration > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), cfg.MaxScanDuration)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}

	return &Collector{
		cfg:          cfg,
		pm:           pm,
		wafDetector:  wafDetector,
		client:       pm.GetClient(),
		limiter:      limiter,
		log:          log.New(os.Stdout, fmt.Sprintf("[%s] ", cfg.Target), log.LstdFlags),
		results: CollectResult{
			Subdomains:  []string{},
			Directories: []DirResult{},
			APIs:        []string{},
			AuthIssues:  make(map[string][]AuthIssue),
			Metadata:    make(map[string]interface{}),
		},
		seenDir:       make(map[string]bool),
		seenAPI:       make(map[string]bool),
		seenSub:       make(map[string]bool),
		respCache:     respCache,
		jsCache:       jsCache,
		cookieJar:     cookieJar,
		previousScan:  make(map[string]uint64),
		verifiedCache: make(map[string]bool),
		ctx:           ctx,
		cancel:        cancel,
		dnsCache:      make(map[string]dnsCacheEntry),
		metrics:       ScanMetrics{StartTime: time.Now()},
	}
}

func (c *Collector) handleSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		c.log.Println("收到中断信号，优雅退出...")
		c.cancel()
	}()
}

func (c *Collector) PrintMetrics() {
	dur := time.Since(c.metrics.StartTime)
	total := c.metrics.RequestsTotal.Load()
	failed := c.metrics.RequestsFailed.Load()
	bytesRecv := c.metrics.BytesReceived.Load()

	fmt.Printf("\n========== 扫描统计 ==========\n")
	fmt.Printf("目标: %s\n", c.cfg.Target)
	fmt.Printf("耗时: %v\n", dur)
	fmt.Printf("请求: %d (失败: %d, 成功率: %.1f%%)\n", total, failed, float64(total-failed)*100/float64(max(total, 1)))
	fmt.Printf("接收: %.2f MB\n", float64(bytesRecv)/1024/1024)
	fmt.Printf("子域名: %d | 目录: %d | API: %d | 漏洞: %d\n",
		len(c.results.Subdomains), len(c.results.Directories), len(c.results.APIs), c.countTotalIssues())
	fmt.Printf("==============================\n")
}

func (c *Collector) countTotalIssues() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, v := range c.results.AuthIssues { n += len(v) }
	return n
}

func (c *Collector) flushCheckpoint() {
	if c.cfg.CacheFile == "" { return }
	c.mu.Lock()
	data, _ := json.MarshalIndent(c.results, "", "  ")
	c.mu.Unlock()
	os.WriteFile(c.cfg.CacheFile+".tmp", data, 0644)
}

func runParallel[T any](c *Collector, items []T, worker func(T), concurrency int) {
	if concurrency <= 0 { concurrency = c.cfg.Threads }
	taskCh := make(chan T, len(items))
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					c.log.Printf("worker panic: %v", r)
				}
			}()
			for item := range taskCh {
				worker(item)
			}
		}()
	}
	for _, it := range items {
		select {
		case <-c.ctx.Done():
		case taskCh <- it:
		}
	}
	close(taskCh)
	wg.Wait()
}

func (c *Collector) detectCMS() string {
	for _, fp := range cmsDB {
		status, body, _ := c.httpGetWithRetry(c.rootURL+fp.Path, nil)
		if status != 200 { continue }
		html := string(body)
		for _, pat := range fp.Patterns {
			if strings.Contains(html, pat) {
				c.cmsName = fp.Name
				c.log.Printf("[CMS] %s", c.cmsName)
				return fp.Name
			}
		}
	}
	return ""
}

func (c *Collector) portScan() []string {
	host := c.extractHost()
	ports := c.mergePorts()
	open := make([]string, 0)
	var mu sync.Mutex
	sem := make(chan struct{}, 50)

	runParallel(c, ports, func(port int) {
		sem <- struct{}{}
		defer func() { <-sem }()
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), defaultConnTimeout)
		if err != nil { return }
		conn.Close()
		scheme := "http"
		if port == 443 { scheme = "https" }
		mu.Lock()
		open = append(open, fmt.Sprintf("%s://%s:%d", scheme, host, port))
		c.log.Printf("[端口] %d OPEN", port)
		mu.Unlock()
	}, 50)
	return open
}

func (c *Collector) extractHost() string {
	host := strings.TrimPrefix(c.rootURL, "https://")
	host = strings.TrimPrefix(host, "http://")
	if i := strings.Index(host, "/"); i > 0 { host = host[:i] }
	return host
}

func (c *Collector) mergePorts() []int {
	ports := make([]int, len(defaultWebPorts))
	copy(ports, defaultWebPorts)
	if c.cfg.ExtraPorts == "" { return ports }
	for _, part := range strings.Split(c.cfg.ExtraPorts, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rng := strings.Split(part, "-")
			if len(rng) == 2 {
				s, e1 := strconv.Atoi(rng[0])
				e, e2 := strconv.Atoi(rng[1])
				if e1 == nil && e2 == nil && s > 0 && e >= s {
					for p := s; p <= e; p++ { ports = append(ports, p) }
				}
			}
		} else if p, err := strconv.Atoi(part); err == nil && p > 0 {
			ports = append(ports, p)
		}
	}
	seen := make(map[int]bool)
	uniq := make([]int, 0, len(ports))
	for _, p := range ports {
		if !seen[p] { seen[p] = true; uniq = append(uniq, p) }
	}
	return uniq
}

func (c *Collector) renderURL(rawurl string) (string, error) {
	ctx, cancel := chromedp.NewContext(c.ctx)
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, defaultRenderTimeout)
	defer cancel()
	var html string
	err := chromedp.Run(ctx,
		chromedp.Navigate(rawurl),
		chromedp.Sleep(defaultRenderWait),
		chromedp.OuterHTML("html", &html),
	)
	return html, err
}

func (c *Collector) fetchWithRendering(rawurl string) (int, string) {
	status, body, _ := c.httpGetWithRetry(rawurl, nil)
	if status == 200 && len(body) < 500 && c.cfg.EnableRendering {
		rendered, err := c.renderURL(rawurl)
		if err == nil && len(rendered) > len(body) {
			c.log.Printf("[渲染] %s", rawurl)
			return 200, rendered
		}
	}
	return status, string(body)
}

func (c *Collector) checkHoneypotOnce() {
	if !c.cfg.EnableHoneypotCheck || c.honeypotChecked { return }
	c.honeypotChecked = true
	testURL := c.rootURL + "/__honeypot_" + randomString(8)
	s, _, _ := c.httpGetWithRetry(testURL, nil)
	if s == 200 {
		c.honeypotDetected = true
		c.log.Printf("[蜜罐] 不存在的路径返回200，可能蜜罐")
	}
}

func (c *Collector) Run() CollectResult {
	c.handleSignals()
	isDomain := !strings.HasPrefix(c.cfg.Target, "http://") && !strings.HasPrefix(c.cfg.Target, "https://")

	if !c.cfg.DirBruteOnly && !c.cfg.APIDiscoverOnly && isDomain {
		c.log.Println("子域名收集...")
		c.subdomainScan()
		c.flushCheckpoint()
	}

	baseURL := c.buildBaseURL(isDomain)
	c.rootURL = c.extractRoot(baseURL)

	if c.cfg.EnableHoneypotCheck { c.checkHoneypotOnce() }

	if c.cfg.EnablePortScan {
		c.log.Println("端口扫描...")
		if ports := c.portScan(); len(ports) > 0 {
			c.mu.Lock()
			c.results.Metadata["open_ports"] = ports
			c.mu.Unlock()
		}
	}

	c.detectCMS()

	if c.cfg.EnableAuthCheck && c.cfg.LowCookie != "" {
		c.validateLowCredential()
	}

	if !c.cfg.SubdomainOnly && !c.cfg.APIDiscoverOnly {
		c.log.Println("目录爆破...")
		c.dirBruteBFS(baseURL)
		c.flushCheckpoint()
	}

	if !c.cfg.SubdomainOnly && !c.cfg.DirBruteOnly {
		c.log.Println("API发现...")
		c.apiDiscoverBFS(baseURL)
		c.flushCheckpoint()
	}

	allURLs := c.collectAllURLs()
	c.log.Printf("共%d个URL，鉴权检测...", len(allURLs))

	if c.cfg.EnableAuthCheck { c.checkAuth(allURLs) }
	if c.cfg.EnableIDOR { c.checkIDOREnhanced(allURLs) }
	if c.cfg.EnableMutate { c.checkBypassEnhanced(allURLs) }

	c.filterOutput()
	c.savePocs()
	c.saveCache()
	c.results.Metadata["target"] = c.cfg.Target
	c.results.Metadata["scan_time"] = time.Now().Format(time.RFC3339)
	if c.cmsName != "" { c.results.Metadata["cms"] = c.cmsName }
	return c.results
}

func (c *Collector) buildBaseURL(isDomain bool) string {
	if isDomain { return "http://" + c.cfg.Target }
	return c.cfg.Target
}

func (c *Collector) extractRoot(baseURL string) string {
	if u, err := url.Parse(baseURL); err == nil { return u.Scheme + "://" + u.Host }
	return baseURL
}

func (c *Collector) collectAllURLs() []string {
	m := make(map[string]bool)
	for _, d := range c.results.Directories { m[d.URL] = true }
	for _, a := range c.results.APIs { m[a] = true }
	r := make([]string, 0, len(m))
	for u := range m { r = append(r, u) }
	return r
}

// 子域名扫描
func (c *Collector) subdomainScan() {
	c.detectWildcard()
	subs := c.loadDict(c.cfg.SubDict)
	if c.cfg.CTLogEnabled {
		subs = append(subs, c.collectFromCTLog(c.cfg.Target)...)
	}
	uniq := make(map[string]bool)
	for _, s := range subs { uniq[s] = true }
	list := make([]string, 0, len(uniq))
	for s := range uniq { list = append(list, s) }
	runParallel(c, list, c.processSubdomain, c.cfg.Threads)
	c.log.Printf("子域名 %d 个有效", len(c.results.Subdomains))
}

func (c *Collector) processSubdomain(sub string) {
	select { case <-c.ctx.Done(): return; default: }
	full := sub + "." + c.cfg.Target
	if c.resolveHostWithCache(full) && !c.isWildcard(full) {
		c.mu.Lock()
		if !c.seenSub[full] {
			c.seenSub[full] = true
			c.results.Subdomains = append(c.results.Subdomains, full)
			c.log.Printf("[子域名] %s", full)
		}
		c.mu.Unlock()
	}
	c.limiter.Wait(c.ctx)
}

func (c *Collector) detectWildcard() {
	testDomain := randomString(10) + "." + c.cfg.Target
	ctx, cancel := context.WithTimeout(c.ctx, 3*time.Second)
	defer cancel()
	var r net.Resolver
	ips, err := r.LookupIP(ctx, "ip4", testDomain)
	if err != nil { return }
	c.wildcardIPs = ips
	status, body, _ := c.httpGetWithRetry("http://"+testDomain, nil)
	if status == 200 {
		l := len(body)
		if l > 512 { l = 512 }
		c.wildcardBody = string(body[:l])
	}
}

func (c *Collector) isWildcard(domain string) bool {
	ctx, cancel := context.WithTimeout(c.ctx, 3*time.Second)
	defer cancel()
	var r net.Resolver
	ips, err := r.LookupIP(ctx, "ip4", domain)
	if err != nil || len(c.wildcardIPs) == 0 { return false }
	for _, ip := range ips {
		for _, wip := range c.wildcardIPs {
			if ip.Equal(wip) { return true }
		}
	}
	return false
}

func (c *Collector) resolveHostWithCache(domain string) bool {
	c.dnsCacheMu.RLock()
	entry, ok := c.dnsCache[domain]
	c.dnsCacheMu.RUnlock()
	if ok && time.Since(entry.ts) < dnsCacheTTLDefault {
		return len(entry.ips) > 0
	}
	if ok {
		c.dnsCacheMu.Lock()
		delete(c.dnsCache, domain)
		c.dnsCacheMu.Unlock()
	}
	ctx, cancel := context.WithTimeout(c.ctx, 3*time.Second)
	defer cancel()
	var r net.Resolver
	ips, err := r.LookupIP(ctx, "ip4", domain)
	if err == nil && len(ips) > 0 {
		c.dnsCacheMu.Lock()
		c.dnsCache[domain] = dnsCacheEntry{ips: ips, ts: time.Now()}
		c.dnsCacheMu.Unlock()
		return true
	}
	return false
}

func (c *Collector) collectFromCTLog(domain string) []string {
	status, body, _ := c.httpGetWithRetry(fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain), nil)
	if status != 200 { return nil }
	var entries []struct{ NameValue string `json:"name_value"` }
	if json.Unmarshal(body, &entries) != nil { return nil }
	m := make(map[string]bool)
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(name)
			if strings.HasSuffix(name, "."+domain) && name != domain && !strings.Contains(name, "*") {
				m[strings.TrimSuffix(name, "."+domain)] = true
			}
		}
	}
	subs := make([]string, 0, len(m))
	for s := range m { subs = append(subs, s) }
	return subs
}

// 目录爆破
func (c *Collector) dirBruteBFS(baseURL string) {
	if c.notFound404 == nil {
		c.notFound404 = c.get404Baseline(baseURL)
	}
	paths := c.loadDict(c.cfg.DirDict)
	if len(paths) == 0 { return }
	layer := []dirQueueItem{{baseURL: baseURL, depth: 0}}
	for depth := 0; depth < c.cfg.MaxDepth; depth++ {
		if len(layer) == 0 || c.ctx.Err() != nil { break }
		layer = c.processDirLayer(layer, paths)
	}
}

func (c *Collector) processDirLayer(layer []dirQueueItem, paths []string) []dirQueueItem {
	taskCh := make(chan dirQueueItem, len(layer))
	resultCh := make(chan DirResult, 100)
	var wg sync.WaitGroup
	for i := 0; i < c.cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil { c.log.Printf("dir worker panic: %v", r) }
			}()
			for item := range taskCh { c.dirBruteItem(item, paths, resultCh) }
		}()
	}
	for _, item := range layer { taskCh <- item }
	close(taskCh)
	go func() { wg.Wait(); close(resultCh) }()

	var next []dirQueueItem
	for res := range resultCh {
		c.mu.Lock()
		c.results.Directories = append(c.results.Directories, res)
		c.mu.Unlock()
		c.log.Printf("[目录] %s [%d] %dB %s", res.URL, res.Status, res.Length, res.Title)
		if c.cfg.Recursive && strings.HasSuffix(res.URL, "/") {
			c.mu.Lock()
			seen := c.seenDir[res.URL]
			if !seen { c.seenDir[res.URL] = true }
			c.mu.Unlock()
			if !seen && res.Depth+1 < c.cfg.MaxDepth {
				next = append(next, dirQueueItem{baseURL: res.URL, depth: res.Depth + 1})
			}
		}
	}
	return next
}

func (c *Collector) dirBruteItem(item dirQueueItem, paths []string, resultCh chan<- DirResult) {
	select { case <-c.ctx.Done(): return; default: }
	for _, p := range paths {
		select { case <-c.ctx.Done(): return; default: }
		if strings.HasPrefix(p, "#") { continue }
		if containsString(c.cfg.StaticExts, strings.ToLower(filepath.Ext(p))) { continue }
		full := strings.TrimRight(item.baseURL, "/") + "/" + strings.TrimLeft(p, "/")
		if err := c.limiter.Wait(c.ctx); err != nil { return }
		status, body, err := c.httpGetWithRetry(full, nil)
		if err != nil || !c.isInterestingStatus(status) { continue }
		bodyLen := len(body)
		title := extractTitle(string(body))
		if c.isNotFound(status, body) { continue }
		if bodyLen < c.cfg.MinBodyLen || (c.cfg.MaxBodyLen > 0 && bodyLen > c.cfg.MaxBodyLen) { continue }
		resultCh <- DirResult{
			URL: full, Status: status, Length: bodyLen,
			Title: title, Hash: fingerprint(body), Depth: item.depth,
		}
	}
}

func (c *Collector) isInterestingStatus(status int) bool {
	return status == 200 || status == 403 || status == 401 || status == 301 || status == 302
}

func (c *Collector) get404Baseline(baseURL string) *NotFoundSignature {
	if !c.cfg.Smart404 {
		u := baseURL + "/__not_found_" + randomString(10)
		status, body, _ := c.httpGetWithRetry(u, nil)
		if status != 404 { return &NotFoundSignature{Status: 404, Length: -1, Hash: 0} }
		return &NotFoundSignature{Status: status, Length: len(body), Title: extractTitle(string(body)), Hash: fingerprint(body)}
	}
	var sigs []NotFoundSignature
	var firstBody []byte
	for i := 0; i < 3; i++ {
		u := baseURL + "/__not_found_" + randomString(12)
		status, body, _ := c.httpGetWithRetry(u, nil)
		if i == 0 { firstBody = body }
		sigs = append(sigs, NotFoundSignature{Status: status, Length: len(body), Title: extractTitle(string(body)), Hash: fingerprint(body)})
		time.Sleep(200 * time.Millisecond)
	}
	avgLen := 0
	for _, sig := range sigs { avgLen += sig.Length }
	avgLen /= len(sigs)
	lowerBody := strings.ToLower(string(firstBody))
	var keywords []string
	for _, kw := range []string{"404", "not found", "找不到", "页面不存在"} {
		if strings.Contains(lowerBody, kw) { keywords = append(keywords, kw) }
	}
	return &NotFoundSignature{
		Status: sigs[0].Status, Length: sigs[0].Length,
		Title: sigs[0].Title, Hash: sigs[0].Hash,
		Keywords: keywords, AvgLength: avgLen,
	}
}

func (c *Collector) isNotFound(status int, body []byte) bool {
	if c.notFound404 == nil || c.notFound404.Length == -1 { return false }
	if status != c.notFound404.Status { return false }

	title := extractTitle(string(body))
	bodyLen := len(body)

	if c.cfg.Smart404 {
		diff := abs(bodyLen - c.notFound404.AvgLength)
		if diff <= int(float64(c.notFound404.AvgLength)*0.1) {
			lowerBody := strings.ToLower(string(body))
			for _, kw := range c.notFound404.Keywords {
				if strings.Contains(lowerBody, kw) { return true }
			}
			if fingerprint(body) == c.notFound404.Hash { return true }
			if title != "" && c.notFound404.Title != "" && title == c.notFound404.Title { return true }
		}
		if status == 200 {
			lowerTitle := strings.ToLower(title)
			for _, kw := range []string{"404", "not found", "找不到", "页面不存在"} {
				if strings.Contains(lowerTitle, kw) { return true }
			}
		}
		if fingerprint(body) == c.notFound404.Hash { return true }
		return false
	}

	if abs(bodyLen-c.notFound404.Length) > 20 { return false }
	if title != "" && c.notFound404.Title != "" && title != c.notFound404.Title { return false }
	return fingerprint(body) == c.notFound404.Hash
}

// API发现
func (c *Collector) apiDiscoverBFS(baseURL string) {
	queue := list.New()
	queue.PushBack(baseURL)
	visited := make(map[string]bool)
	for queue.Len() > 0 {
		select { case <-c.ctx.Done(): return; default: }
		e := queue.Front()
		queue.Remove(e)
		cur := e.Value.(string)
		if visited[cur] { continue }
		visited[cur] = true
		status, html := c.fetchWithRendering(cur)
		if status != 200 { continue }
		for _, link := range extractLinks(html, cur) {
			if strings.Contains(link, baseURL) && !strings.Contains(link, "logout") && !visited[link] {
				queue.PushBack(link)
			}
		}
		for _, api := range extractAPIEndpointsEnhanced(html, c.cfg.StaticExts) {
			full := resolveURL(cur, api)
			if full != "" && strings.HasPrefix(full, baseURL) {
				c.mu.Lock()
				if !c.seenAPI[full] {
					c.seenAPI[full] = true
					c.results.APIs = append(c.results.APIs, full)
					c.log.Printf("[API] %s", full)
				}
				c.mu.Unlock()
			}
		}
		if c.cfg.DeepJS {
			for _, jsFile := range extractJSFiles(html, cur) {
				if _, ok := c.jsCache.Get(jsFile); ok { continue }
				c.jsCache.Add(jsFile, true)
				jsStatus, jsBody, _ := c.httpGetWithRetry(jsFile, nil)
				if jsStatus != 200 { continue }
				for _, api := range extractAPIsFromJS(string(jsBody), cur) {
					if strings.HasPrefix(api, baseURL) {
						c.mu.Lock()
						if !c.seenAPI[api] {
							c.seenAPI[api] = true
							c.results.APIs = append(c.results.APIs, api)
							c.log.Printf("[API-JS] %s", api)
						}
						c.mu.Unlock()
					}
				}
			}
		}
	}
}

// 凭证验证
func (c *Collector) validateLowCredential() {
	for _, path := range c.cfg.AuthCheckPaths {
		u := c.rootURL + path
		status, body, _ := c.httpGetWithRetry(u, c.cfg.LowHeaders)
		if status == 200 || status == 201 {
			c.lowValid = true
			c.lowFingerprint = fingerprint(cleanDynamicContent(body))
			c.log.Printf("低权限凭证有效(%s)", u)
			return
		}
	}
	c.log.Printf("低权限凭证无效")
}

func (c *Collector) checkAuth(urls []string) {
	for _, u := range urls {
		select { case <-c.ctx.Done(): return; default: }
		anonStatus, anonBody, _ := c.getCachedResponse(u, nil)
		if anonStatus == 200 || anonStatus == 201 {
			if data := c.tryFetchRealData(u); data != "" {
				c.addIssue("high", AuthIssue{
					URL: u, Type: "unauth",
					Detail:     "未授权可直接访问，返回: " + data,
					Confidence: "high",
					PoC:        fmt.Sprintf("curl -X GET %q", u),
				})
				logHigh("未授权访问: %s", u)
			}
			continue
		}
		if c.lowValid {
			lowStatus, lowBody, _ := c.getCachedResponse(u, c.cfg.LowHeaders)
			if lowStatus == 200 || lowStatus == 201 {
				if fingerprint(anonBody) != fingerprint(lowBody) {
					if data := c.tryFetchRealData(u); data != "" {
						c.addIssue("medium", AuthIssue{
							URL: u, Type: "low_auth",
							Detail:     "普通用户越权访问，返回: " + data,
							Confidence: "medium",
							PoC:        fmt.Sprintf("curl -X GET %q -H 'Cookie: %s'", u, c.cfg.LowCookie),
						})
						logMedium("普通用户越权: %s", u)
					}
				}
			}
		}
	}
}

func (c *Collector) tryFetchRealData(rawurl string) string {
	c.mu.Lock()
	if c.verifiedCache[rawurl] { c.mu.Unlock(); return "" }
	c.verifiedCache[rawurl] = true
	c.mu.Unlock()
	urls := []string{rawurl}
	if strings.Contains(rawurl, "/0") {
		urls = append(urls, strings.Replace(rawurl, "/0", "/1", 1))
	}
	for _, u := range urls {
		status, body, _ := c.getCachedResponse(u, nil)
		if status != 200 && status != 201 { continue }
		s := string(body)
		if strings.Contains(s, "email") || strings.Contains(s, "username") ||
			strings.Contains(s, "phone") || strings.Contains(s, "\"id\"") {
			if len(s) > 200 { s = s[:200] + "..." }
			return s
		}
	}
	return ""
}

// IDOR检测
func (c *Collector) checkIDOREnhanced(urls []string) {
	uuidRe := regexp.MustCompile(`/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`)
	for _, u := range urls {
		select { case <-c.ctx.Done(): return; default: }
		anonStatus, anonBody, _ := c.getCachedResponse(u, nil)
		if anonStatus != 401 && anonStatus != 403 { continue }
		var idList []string
		if c.lowValid {
			lowStatus, lowBody, _ := c.getCachedResponse(u, c.cfg.LowHeaders)
			if lowStatus == 200 || lowStatus == 201 {
				for _, id := range extractIDsFromJSON(string(lowBody)) { idList = append(idList, strconv.Itoa(id)) }
				for _, m := range uuidRe.FindAllStringSubmatch(string(lowBody), -1) {
					if len(m) > 1 { idList = append(idList, m[1]) }
				}
			}
		}
		if len(idList) == 0 {
			for _, id := range extractIDsFromJSON(string(anonBody)) { idList = append(idList, strconv.Itoa(id)) }
		}
		idList = uniqueStrings(idList)
		if len(idList) == 0 { continue }
		for _, id := range idList {
			if isAllDigits(id) {
				idInt, _ := strconv.Atoi(id)
				testVals := []int{idInt - 1, idInt + 1, idInt + 2}
				if idInt > 1000 { testVals = append(testVals, 1) }
				for _, nid := range testVals {
					if nid <= 0 || nid > 10000 { continue }
					newURL := strings.Replace(u, "/"+id, fmt.Sprintf("/%d", nid), 1)
					newURL = strings.Replace(newURL, "="+id, fmt.Sprintf("=%d", nid), -1)
					lowStatus, lowBody, _ := c.getCachedResponse(newURL, c.cfg.LowHeaders)
					if lowStatus == 200 || lowStatus == 201 {
						if fingerprint(lowBody) != fingerprint(anonBody) {
							c.addIssue("idor", AuthIssue{
								URL: newURL, Type: "idor",
								Detail:     fmt.Sprintf("IDOR: %s -> %d", id, nid),
								Confidence: "high",
								PoC:        fmt.Sprintf("curl -X GET %q -H 'Cookie: %s'", newURL, c.cfg.LowCookie),
							})
							logHigh("IDOR: %s", newURL)
							break
						}
					}
				}
			} else if uuidRe.MatchString(id) {
				nid := id[:len(id)-1] + string(byte('0')+(id[len(id)-1]-'0'+1)%10)
				newURL := strings.Replace(u, id, nid, 1)
				lowStatus, lowBody, _ := c.getCachedResponse(newURL, c.cfg.LowHeaders)
				if lowStatus == 200 || lowStatus == 201 {
					if fingerprint(lowBody) != fingerprint(anonBody) {
						c.addIssue("idor", AuthIssue{
							URL: newURL, Type: "idor",
							Detail:     fmt.Sprintf("IDOR: UUID %s", nid),
							Confidence: "medium",
							PoC:        fmt.Sprintf("curl -X GET %q -H 'Cookie: %s'", newURL, c.cfg.LowCookie),
						})
						logHigh("IDOR(UUID): %s", newURL)
					}
				}
			}
		}
	}
}

// 越权绕过检测
type MutatorEnhanced struct {
	c          *Collector
	origURL    string
	origStatus int
	origFP     uint64
	parsed     *url.URL
	results    []BypassResult
}

type BypassResult struct {
	URL, Type, Detail, PoC string
}

func NewMutatorEnhanced(c *Collector, rawURL string) *MutatorEnhanced {
	parsed, _ := url.Parse(rawURL)
	return &MutatorEnhanced{c: c, origURL: rawURL, parsed: parsed}
}

func (m *MutatorEnhanced) Init() error {
	status, body, _ := m.c.getCachedResponse(m.origURL, nil)
	m.origStatus, m.origFP = status, fingerprint(body)
	return nil
}

func (m *MutatorEnhanced) isBypass(status int, body []byte) bool {
	if m.origStatus != 401 && m.origStatus != 403 { return false }
	if status == 200 || status == 201 { return true }
	bad := map[int]bool{401: true, 403: true, 404: true, 500: true, 502: true, 503: true}
	return status != m.origStatus && !bad[status] && fingerprint(body) != m.origFP
}

func (m *MutatorEnhanced) methodMutate() {
	for _, meth := range []string{"POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} {
		status, body, _ := m.c.httpRequest(m.origURL, meth, nil, m.c.cfg.LowHeaders)
		if m.isBypass(status, body) {
			m.results = append(m.results, BypassResult{
				URL: m.origURL, Type: "method",
				Detail: fmt.Sprintf("使用%s方法绕过", meth),
				PoC:    fmt.Sprintf("curl -X %s %q -H 'Cookie: %s'", meth, m.origURL, m.c.cfg.LowCookie),
			})
			return
		}
	}
}

func (m *MutatorEnhanced) pathMutate() {
	path := strings.TrimPrefix(m.parsed.Path, "/")
	for _, mp := range []string{
		"//" + path, "/" + path + "/", "/" + path + "/.", "/" + path + "/..",
		"/%2f" + path, "/" + path + ";", "/" + path + "..;/", "/.;/" + path,
	} {
		norm := strings.ReplaceAll("/"+strings.TrimLeft(mp, "/"), "//", "/")
		if strings.HasPrefix(mp, "//") { norm = "//" + strings.TrimPrefix(norm, "/") }
		newURL := m.parsed.Scheme + "://" + m.parsed.Host + norm
		if m.parsed.RawQuery != "" { newURL += "?" + m.parsed.RawQuery }
		status, body, _ := m.c.getCachedResponse(newURL, m.c.cfg.LowHeaders)
		if m.isBypass(status, body) {
			m.results = append(m.results, BypassResult{
				URL: newURL, Type: "path",
				Detail: fmt.Sprintf("路径变异: %s", mp),
				PoC:    fmt.Sprintf("curl -X GET %q -H 'Cookie: %s'", newURL, m.c.cfg.LowCookie),
			})
			return
		}
	}
}

func (m *MutatorEnhanced) headerMutate() {
	for _, h := range []map[string]string{
		{"X-Original-URL": m.parsed.Path}, {"X-Rewrite-URL": m.parsed.Path},
		{"X-Forwarded-For": "127.0.0.1"}, {"X-Real-IP": "127.0.0.1"},
		{"X-Remote-IP": "127.0.0.1"}, {"X-Client-IP": "127.0.0.1"},
		{"X-Proxy-IP": "127.0.0.1"}, {"Forwarded": "for=127.0.0.1"},
	} {
		merged := make(map[string]string)
		for k, v := range m.c.cfg.LowHeaders { merged[k] = v }
		for k, v := range h { merged[k] = v }
		status, body, _ := m.c.getCachedResponse(m.origURL, merged)
		if m.isBypass(status, body) {
			for k, v := range h {
				m.results = append(m.results, BypassResult{
					URL: m.origURL, Type: "header",
					Detail: fmt.Sprintf("添加头部 %s: %s", k, v),
					PoC:    fmt.Sprintf("curl -X GET %q -H '%s: %s' -H 'Cookie: %s'", m.origURL, k, v, m.c.cfg.LowCookie),
				})
				return
			}
		}
	}
}

func (m *MutatorEnhanced) Run() []BypassResult {
	if m.origStatus != 401 && m.origStatus != 403 { return nil }
	m.methodMutate()
	if len(m.results) == 0 { m.pathMutate() }
	if len(m.results) == 0 { m.headerMutate() }
	return m.results
}

func (c *Collector) checkBypassEnhanced(urls []string) {
	for _, u := range urls {
		select { case <-c.ctx.Done(): return; default: }
		mut := NewMutatorEnhanced(c, u)
		mut.Init()
		for _, res := range mut.Run() {
			c.addIssue("bypass", AuthIssue{
				URL: res.URL, Type: "bypass",
				Detail: res.Detail, Confidence: "high", PoC: res.PoC,
			})
			logHigh("鉴权绕过: %s (%s)", res.URL, res.Type)
		}
	}
}

func extractIDsFromJSON(text string) []int {
	var ids []int
	seen := make(map[int]bool)
	var parse func(interface{})
	parse = func(data interface{}) {
		switch v := data.(type) {
		case map[string]interface{}:
			for key, val := range v {
				if strings.Contains(strings.ToLower(key), "id") {
					if num, ok := val.(float64); ok && num >= 1 && num <= 10000 && !seen[int(num)] {
						seen[int(num)] = true
						ids = append(ids, int(num))
					}
				}
				parse(val)
			}
		case []interface{}:
			for _, item := range v { parse(item) }
		}
	}
	var obj interface{}
	if json.Unmarshal([]byte(text), &obj) == nil { parse(obj) }
	return ids
}

func fingerprint(body []byte) uint64 {
	h := fnv.New64a()
	h.Write(body)
	return h.Sum64()
}

// HTTP请求
func (c *Collector) getCachedResponse(rawurl string, headers map[string]string) (int, []byte, uint64) {
	key := c.cacheKey(rawurl, headers)
	if cached, ok := c.respCache.Get(key); ok {
		cr := cached.(cachedResponse)
		if time.Since(cr.ts) < time.Duration(c.cfg.CacheTTL)*time.Second { return cr.status, cr.body, cr.fp }
		c.respCache.Remove(key)
	}
	status, body, err := c.httpGetWithRetry(rawurl, headers)
	if err != nil { return 0, nil, 0 }
	fp := fingerprint(body)
	c.respCache.Add(key, cachedResponse{status: status, body: body, fp: fp, ts: time.Now()})
	return status, body, fp
}

func (c *Collector) cacheKey(rawurl string, headers map[string]string) string {
	if len(headers) == 0 { return rawurl }
	keys := make([]string, 0, len(headers))
	for k := range headers { keys = append(keys, k) }
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(rawurl)
	b.WriteByte('|')
	for _, k := range keys { b.WriteString(k); b.WriteByte('='); b.WriteString(headers[k]); b.WriteByte(';') }
	return b.String()
}

func (c *Collector) httpGetWithRetry(rawurl string, headers map[string]string) (int, []byte, error) {
	var lastErr error
	for i := 0; i <= c.cfg.RetryCount; i++ {
		select { case <-c.ctx.Done(): return 0, nil, c.ctx.Err(); default: }
		status, body, err := c.httpRequest(rawurl, "GET", nil, headers)
		if err == nil { return status, body, nil }
		lastErr = err
		time.Sleep(time.Duration(c.cfg.RetryWaitMin*(1<<i)) * time.Millisecond)
	}
	return 0, nil, lastErr
}

func (c *Collector) adjustRateLimitOnFail() {
	c.consecutiveFailsMu.Lock()
	defer c.consecutiveFailsMu.Unlock()
	c.consecutiveFails++
	if c.consecutiveFails >= 3 {
		limit := float64(c.cfg.RateLimit) / 2
		if limit < 1 { limit = 1 }
		c.limiter.SetLimit(rate.Limit(limit))
	}
}

func (c *Collector) adjustRateLimitOnSuccess() {
	c.consecutiveFailsMu.Lock()
	defer c.consecutiveFailsMu.Unlock()
	if c.consecutiveFails > 0 { c.consecutiveFails-- }
	if c.consecutiveFails == 0 { c.limiter.SetLimit(rate.Limit(c.cfg.RateLimit)) }
}

func (c *Collector) addPenalty() {
	if np := atomic.AddInt32(&c.penaltyWeight, 1); np > 10 { atomic.StoreInt32(&c.penaltyWeight, 10) }
}

func (c *Collector) applyDelay() {
	base := 500
	if c.cfg.StealthMode { base = 1500 }
	base += int(atomic.LoadInt32(&c.penaltyWeight)) * 200
	if base > 3000 { base = 3000 }
	time.Sleep(time.Duration(base+rand.Intn(1000)) * time.Millisecond)
}

func (c *Collector) httpRequest(rawurl, method string, body io.Reader, headers map[string]string) (int, []byte, error) {
	if c.cfg.StableMode {
		defer func() {
			if r := recover(); r != nil { c.log.Printf("HTTP崩溃: %v", r) }
		}()
	}
	c.applyDelay()
	if err := c.limiter.Wait(c.ctx); err != nil { return 0, nil, err }
	req, err := c.buildRequest(rawurl, method, body, headers)
	if err != nil { return 0, nil, err }
	c.addCookies(req)

	c.metrics.RequestsTotal.Add(1)
	resp, err := c.client.Do(req)
	if err != nil {
		c.metrics.RequestsFailed.Add(1)
		c.handleRequestError(err)
		return 0, nil, err
	}
	defer resp.Body.Close()

	data, err := c.readResponseBody(resp)
	c.metrics.BytesReceived.Add(int64(len(data)))
	if err != nil { return resp.StatusCode, data, err }

	c.storeCookies(req, resp)
	if blocked, code := c.isBlocked(resp, data); blocked { return code, data, fmt.Errorf("blocked") }
	c.adjustRateLimitOnSuccess()
	return resp.StatusCode, data, nil
}

func (c *Collector) buildRequest(rawurl, method string, body io.Reader, headers map[string]string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(c.ctx, method, rawurl, body)
	if err != nil { return nil, err }

	if c.cfg.StealthMode {
		req.Header = make(http.Header)
		req.Header.Set("Host", req.URL.Host)
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Cache-Control", "max-age=0")
		req.Header.Set("sec-ch-ua", `"Chromium";v="125", "Not.A/Brand";v="24", "Google Chrome";v="125"`)
		req.Header.Set("sec-ch-ua-mobile", "?0")
		req.Header.Set("sec-ch-ua-platform", `"Windows"`)
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("User-Agent", getUAForTarget(c.rootURL))
		req.Header.Set("Accept", randomAccept())
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Accept-Encoding", randomAcceptEncoding())
		req.Header.Set("Accept-Language", randomAcceptLanguage())
		for k, v := range headers { req.Header.Set(k, v) }
		if strings.Contains(rawurl, c.rootURL) { req.Header.Set("Referer", c.rootURL) }
	} else {
		req.Header.Set("User-Agent", getUAForTarget(c.rootURL))
		req.Header.Set("Accept", randomAccept())
		req.Header.Set("Accept-Encoding", randomAcceptEncoding())
		req.Header.Set("Accept-Language", randomAcceptLanguage())
		for k, v := range headers { req.Header.Set(k, v) }
	}
	for k, v := range c.cfg.CustomHeaders {
		if req.Header.Get(k) == "" { req.Header.Set(k, v) }
	}
	return req, nil
}

func (c *Collector) addCookies(req *http.Request) {
	if cookies, ok := c.cookieJar.Get(req.URL.Host); ok {
		for _, cookie := range cookies.([]*http.Cookie) { req.AddCookie(cookie) }
	}
}

func (c *Collector) readResponseBody(resp *http.Response) ([]byte, error) {
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "video/") ||
		strings.HasPrefix(ct, "audio/") || strings.Contains(ct, "font") ||
		strings.Contains(ct, "application/octet-stream") {
		io.Copy(io.Discard, resp.Body)
		return []byte{}, nil
	}
	maxSize := c.cfg.MaxResponseSize
	if maxSize <= 0 { maxSize = 2 * 1024 * 1024 }
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if int64(len(data)) > maxSize { return data[:maxSize], nil }
	return data, nil
}

func (c *Collector) storeCookies(req *http.Request, resp *http.Response) {
	if len(resp.Cookies()) > 0 { c.cookieJar.Add(req.URL.Host, resp.Cookies()) }
}

func (c *Collector) isBlocked(resp *http.Response, body []byte) (bool, int) {
	if resp.StatusCode == 429 || resp.StatusCode == 403 {
		c.addPenalty(); c.pm.ForceRotate(); c.adjustRateLimitOnFail()
		return true, resp.StatusCode
	}
	lowerBody := strings.ToLower(string(body))
	for _, kw := range c.wafDetector.Keywords() {
		if strings.Contains(lowerBody, kw) {
			c.addPenalty(); c.pm.ForceRotate(); c.adjustRateLimitOnFail()
			return true, resp.StatusCode
		}
	}
	return false, 0
}

func (c *Collector) handleRequestError(err error) {
	c.addPenalty()
	if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "429") {
		c.pm.ForceRotate(); c.adjustRateLimitOnFail()
	}
}

// 输出
func (c *Collector) addIssue(category string, issue AuthIssue) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.results.AuthIssues[category]; !ok {
		c.results.AuthIssues[category] = []AuthIssue{}
	}
	c.results.AuthIssues[category] = append(c.results.AuthIssues[category], issue)
}

func (c *Collector) savePocs() {
	if c.cfg.PocOutputDir == "" { return }
	os.MkdirAll(c.cfg.PocOutputDir, 0755)
	for cat, issues := range c.results.AuthIssues {
		for i, issue := range issues {
			name := fmt.Sprintf("%s/%s_%d_%s.txt", c.cfg.PocOutputDir, cat, i, hashString(issue.URL)[:8])
			content := fmt.Sprintf("漏洞类型: %s\nURL: %s\n详情: %s\n置信度: %s\nPoC:\n%s\n",
				issue.Type, issue.URL, issue.Detail, issue.Confidence, issue.PoC)
			os.WriteFile(name, []byte(content), 0644)
		}
	}
	c.log.Printf("PoC已保存至 %s", c.cfg.PocOutputDir)
}

func (c *Collector) loadDict(path string) []string {
	f, err := os.Open(path)
	if err != nil { c.log.Printf("打开字典失败: %v", err); return nil }
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") { lines = append(lines, line) }
	}
	return lines
}

func (c *Collector) loadCache() {
	data, err := os.ReadFile(c.cfg.CacheFile)
	if err != nil { return }
	var m map[string]uint64
	if json.Unmarshal(data, &m) != nil { return }
	c.previousScan = m
}

func (c *Collector) saveCache() {
	if c.cfg.CacheFile == "" { return }
	m := make(map[string]uint64)
	for _, d := range c.results.Directories { m[d.URL] = d.Hash }
	data, _ := json.Marshal(m)
	os.WriteFile(c.cfg.CacheFile, data, 0644)
}

func (c *Collector) filterOutput() {
	dirs := make([]DirResult, 0, len(c.results.Directories))
	for _, d := range c.results.Directories {
		if c.shouldKeepDir(d) { dirs = append(dirs, d) }
	}
	if c.cfg.CacheFile != "" && len(c.previousScan) > 0 {
		final := make([]DirResult, 0, len(dirs))
		for _, d := range dirs {
			if oldHash, ok := c.previousScan[d.URL]; !ok || oldHash != d.Hash { final = append(final, d) }
		}
		dirs = final
	}
	c.results.Directories = dirs

	apis := make([]string, 0, len(c.results.APIs))
	for _, a := range c.results.APIs {
		if c.shouldKeepAPI(a) { apis = append(apis, a) }
	}
	if c.cfg.CacheFile != "" && len(c.previousScan) > 0 {
		final := make([]string, 0, len(apis))
		for _, a := range apis {
			if _, ok := c.previousScan[a]; !ok { final = append(final, a) }
		}
		apis = final
	}
	c.results.APIs = apis
}

func (c *Collector) shouldKeepDir(d DirResult) bool {
	if c.cfg.FilterStatic && containsString(c.cfg.StaticExts, strings.ToLower(filepath.Ext(d.URL))) {
		return false
	}
	if d.Status == 200 {
		lt := strings.ToLower(d.Title)
		if strings.Contains(lt, "not found") || strings.Contains(lt, "404") ||
			strings.Contains(lt, "page not found") || strings.Contains(lt, "找不到") {
			return false
		}
		return d.Length >= 100
	}
	return d.Status == 301 || d.Status == 302 || d.Status == 403 || d.Status == 401
}

func (c *Collector) shouldKeepAPI(api string) bool {
	if c.cfg.FilterStatic && containsString(c.cfg.StaticExts, strings.ToLower(filepath.Ext(api))) {
		return false
	}
	lower := strings.ToLower(api)
	return strings.Contains(lower, "/api") || strings.Contains(lower, "/v1") ||
		strings.Contains(lower, "/v2") || strings.Contains(lower, "/v3") ||
		strings.Contains(lower, "/graphql") || strings.Contains(lower, "/swagger") ||
		strings.Contains(lower, "/rest") || strings.Contains(lower, "/rpc")
}
