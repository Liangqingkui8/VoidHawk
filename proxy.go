package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

type ProxyManager struct {
	mu         sync.RWMutex
	enable     bool
	proxies    []string
	currentIdx int
	transport  *http.Transport
	client     *http.Client
	cfg        *Config
	ja3Enabled bool
	ja3IDs     []utls.ClientHelloID
}

func NewProxyManager(cfg *Config, ja3Enabled bool) *ProxyManager {
	pm := &ProxyManager{
		enable:     cfg.EnableProxyRotation,
		cfg:        cfg,
		ja3Enabled: ja3Enabled,
		ja3IDs: []utls.ClientHelloID{
			utls.HelloChrome_120,
			utls.HelloFirefox_120,
			utls.HelloRandomized,
		},
	}
	pm.initTransport()
	return pm
}

func (pm *ProxyManager) initTransport() {
	if pm.ja3Enabled {
		pm.transport = pm.buildJA3Transport()
	} else {
		pm.transport = pm.buildStandardTransport()
	}
	pm.client = &http.Client{
		Transport: pm.transport,
		Timeout:   time.Duration(pm.cfg.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 { return http.ErrUseLastResponse }
			return nil
		},
	}
}

func (pm *ProxyManager) buildJA3Transport() *http.Transport {
	dialer := &net.Dialer{
		Timeout:   time.Duration(pm.cfg.Timeout) * time.Second,
		KeepAlive: 30 * time.Second,
	}
	nextProtos := []string{"h2", "http/1.1"}
	if pm.cfg.ForceHTTP11 { nextProtos = []string{"http/1.1"} }

	return &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		MaxConnsPerHost:     50,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
		ForceAttemptHTTP2:   !pm.cfg.ForceHTTP11,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil { return nil, err }
			host, _, err := net.SplitHostPort(addr)
			if err != nil { host = addr }
			tlsConfig := &utls.Config{
				InsecureSkipVerify: pm.cfg.InsecureSkipVerify,
				ServerName:         host,
				NextProtos:         nextProtos,
			}
			id := pm.ja3IDs[rand.Intn(len(pm.ja3IDs))]
			uconn := utls.UClient(conn, tlsConfig, id)
			if err := uconn.Handshake(); err != nil {
				conn.Close()
				return nil, fmt.Errorf("TLS握手失败: %w", err)
			}
			return uconn, nil
		},
		Proxy: pm.getProxyFunc(),
	}
}

func (pm *ProxyManager) buildStandardTransport() *http.Transport {
	nextProtos := []string{"h2", "http/1.1"}
	if pm.cfg.ForceHTTP11 { nextProtos = []string{"http/1.1"} }

	return &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		MaxConnsPerHost:     50,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableCompression:  false,
		ForceAttemptHTTP2:   !pm.cfg.ForceHTTP11,
		Proxy:               pm.getProxyFunc(),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: pm.cfg.InsecureSkipVerify,
			NextProtos:         nextProtos,
		},
	}
}

func (pm *ProxyManager) getProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		pm.mu.RLock()
		defer pm.mu.RUnlock()
		if !pm.enable || len(pm.proxies) == 0 { return nil, nil }
		return url.Parse(pm.proxies[pm.currentIdx])
	}
}

func (pm *ProxyManager) checkProxyAlive(proxyStr string) bool {
	if proxyStr == "" { return false }
	u, err := url.Parse(proxyStr)
	if err != nil || u.Host == "" { return false }
	conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil { return false }
	conn.Close()
	return true
}

func (pm *ProxyManager) LoadProxies(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("打开代理文件失败: %v", err)
		pm.enable = false
		return
	}
	defer file.Close()

	var rawProxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }
		rawProxies = append(rawProxies, line)
	}
	if len(rawProxies) == 0 { pm.enable = false; return }

	alive := make([]string, 0, len(rawProxies))
	for _, p := range rawProxies {
		if pm.checkProxyAlive(p) { alive = append(alive, p) }
	}

	pm.mu.Lock()
	pm.proxies = alive
	if len(alive) > 0 {
		pm.currentIdx = rand.Intn(len(alive))
		pm.enable = true
	} else {
		pm.enable = false
	}
	pm.mu.Unlock()
	log.Printf("代理池: %d个可用", len(pm.proxies))
}

func (pm *ProxyManager) ForceRotate() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if !pm.enable || len(pm.proxies) <= 1 { return }
	pm.currentIdx = (pm.currentIdx + 1) % len(pm.proxies)
	log.Printf("轮换代理 -> %s", pm.proxies[pm.currentIdx])
}

func (pm *ProxyManager) GetClient() *http.Client { return pm.client }
