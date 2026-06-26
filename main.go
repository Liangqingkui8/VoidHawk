package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	target := flag.String("target", "", "目标URL或域名")
	threads := flag.Int("threads", 20, "并发数")
	rate := flag.Int("rate", 50, "每秒请求数")
	timeout := flag.Int("timeout", 10, "HTTP超时秒数")
	retry := flag.Int("retry", 2, "重试次数")
	maxDepth := flag.Int("depth", 3, "目录递归深度")
	subDict := flag.String("sub", "subdomains.txt", "子域名字典")
	dirDict := flag.String("dir", "directories.txt", "目录字典")
	proxyFile := flag.String("proxy", "", "代理列表文件")
	output := flag.String("output", "result.json", "输出JSON文件")
	pocDir := flag.String("poc", "pocs", "PoC输出目录")
	cacheFile := flag.String("cache", "scan_cache.json", "缓存文件")
	cookie := flag.String("cookie", "", "Cookie, 格式 'key1=val1; key2=val2'")
	customHeader := flag.String("header", "", "自定义请求头, 格式 key:value,key2:value2")

	subOnly := flag.Bool("subonly", false, "仅子域名")
	dirOnly := flag.Bool("dironly", false, "仅目录爆破")
	apiOnly := flag.Bool("apionly", false, "仅API发现")
	noRecurse := flag.Bool("no-recurse", false, "禁用递归")
	noSmart := flag.Bool("no-smart404", false, "禁用智能404")
	noDeepJS := flag.Bool("no-deepjs", false, "禁用深度JS分析")
	noFilter := flag.Bool("no-filter", false, "不过滤静态文件")
	stealth := flag.Bool("stealth", false, "隐身模式")
	noAuth := flag.Bool("no-auth", false, "禁用鉴权检测")
	noIDOR := flag.Bool("no-idor", false, "禁用IDOR检测")
	noBypass := flag.Bool("no-bypass", false, "禁用绕过检测")
	noCTLog := flag.Bool("no-ctlog", false, "禁用crt.sh")
	insecure := flag.Bool("insecure", false, "跳过TLS验证")
	ja3 := flag.Bool("ja3", true, "JA3指纹随机化")
	forceHTTP11 := flag.Bool("force-http11", false, "强制HTTP/1.1")
	render := flag.Bool("render", false, "JS渲染(需要Chromium)")
	portScan := flag.Bool("port-scan", false, "轻量端口扫描")
	extraPorts := flag.String("ports", "", "额外端口, 如 80,443,8080-8090")
	maxDuration := flag.Duration("max-duration", 30*time.Minute, "最大扫描时长")
	detectHoneypot := flag.Bool("detect-honeypot", false, "蜜罐检测")

	flag.Parse()
	printBanner()

	if *target == "" {
		log.Fatal("必须指定 -target")
	}

	cfg := DefaultConfig()
	cfg.Target = *target
	cfg.Threads = *threads
	cfg.RateLimit = *rate
	cfg.Timeout = *timeout
	cfg.RetryCount = *retry
	cfg.MaxDepth = *maxDepth
	cfg.SubDict = *subDict
	cfg.DirDict = *dirDict
	cfg.ProxyFile = *proxyFile
	cfg.PocOutputDir = *pocDir
	cfg.CacheFile = *cacheFile

	cfg.SubdomainOnly = *subOnly
	cfg.DirBruteOnly = *dirOnly
	cfg.APIDiscoverOnly = *apiOnly
	cfg.Recursive = !*noRecurse
	cfg.Smart404 = !*noSmart
	cfg.DeepJS = !*noDeepJS
	cfg.FilterStatic = !*noFilter
	cfg.StealthMode = *stealth
	cfg.EnableAuthCheck = !*noAuth
	cfg.EnableIDOR = !*noIDOR
	cfg.EnableMutate = !*noBypass
	cfg.CTLogEnabled = !*noCTLog
	cfg.InsecureSkipVerify = *insecure
	cfg.JA3Enabled = *ja3
	cfg.ForceHTTP11 = *forceHTTP11
	cfg.EnableProxyRotation = *proxyFile != ""
	cfg.MaxScanDuration = *maxDuration
	cfg.EnableRendering = *render
	cfg.EnablePortScan = *portScan
	cfg.ExtraPorts = *extraPorts
	cfg.EnableHoneypotCheck = *detectHoneypot

	if *cookie != "" {
		cfg.LowCookie = *cookie
		cfg.LowHeaders["Cookie"] = *cookie
	}

	if *customHeader != "" {
		for _, pair := range strings.Split(*customHeader, ",") {
			kv := strings.SplitN(pair, ":", 2)
			if len(kv) == 2 {
				cfg.CustomHeaders[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	pm := NewProxyManager(&cfg, cfg.JA3Enabled)
	if cfg.EnableProxyRotation {
		pm.LoadProxies(cfg.ProxyFile)
	}

	wafDetector := NewWAFDetector()
	collector := NewCollector(cfg, pm, wafDetector)

	result := collector.Run()
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("序列化结果失败: %v", err)
	}
	if err := os.WriteFile(*output, data, 0644); err != nil {
		log.Fatalf("写入结果文件失败: %v", err)
	}

	collector.PrintMetrics()
	log.Printf("扫描完成，结果已保存至 %s", *output)
}
