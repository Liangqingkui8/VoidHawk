package main

import (
	"fmt"
	"hash/fnv"
	"log"
	"math/rand"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	reTitle   = regexp.MustCompile(`<title>(.*?)</title>`)
	reLink    = regexp.MustCompile(`(?:href|src)=["']([^"']+)["']`)
	reAPI     = regexp.MustCompile(`(?i)["'\x60](/(?:api|rest|v[0-9]|graphql|swagger|docs|service|endpoint)/[^"'\x60\s,;)]*)`)
	reFetch   = regexp.MustCompile(`(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["']([^"']+)["']`)
	reJSRoute = regexp.MustCompile(`(?i)path\s*:\s*["'\x60](/[^"'\x60]+)["'\x60]`)
	reTimeClean = regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`)
	reRandClean = regexp.MustCompile(`[0-9a-f]{8,}`)
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
}

var acceptValues = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"application/json, text/plain, */*",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
}
var acceptEncodingValues = []string{"gzip, deflate, br, zstd", "gzip, deflate, br", "gzip, deflate"}
var acceptLanguageValues = []string{
	"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
	"en-US,en;q=0.9",
	"zh-TW,zh;q=0.9,en;q=0.8",
	"ja,en;q=0.9",
}

func randomUA() string                        { return userAgents[rand.Intn(len(userAgents))] }
func randomAccept() string                    { return acceptValues[rand.Intn(len(acceptValues))] }
func randomAcceptEncoding() string            { return acceptEncodingValues[rand.Intn(len(acceptEncodingValues))] }
func randomAcceptLanguage() string            { return acceptLanguageValues[rand.Intn(len(acceptLanguageValues))] }

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[rand.Intn(62)]
	}
	return string(b)
}

func randomDelayMS(base, jitter int) int { return base + rand.Intn(jitter) }

func extractTitle(html string) string {
	m := reTitle.FindStringSubmatch(html)
	if len(m) > 1 { return strings.TrimSpace(m[1]) }
	return ""
}

func extractLinks(html, base string) []string {
	var links []string
	for _, m := range reLink.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			u := resolveURL(base, m[1])
			if u != "" && !strings.HasPrefix(u, "javascript:") && !strings.HasPrefix(u, "mailto:") && !strings.HasPrefix(u, "#") {
				links = append(links, u)
			}
		}
	}
	return links
}

func extractJSFiles(html, base string) []string {
	var jsFiles []string
	for _, m := range reLink.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			u := resolveURL(base, m[1])
			if u != "" && strings.HasSuffix(strings.ToLower(u), ".js") { jsFiles = append(jsFiles, u) }
		}
	}
	return uniqueStrings(jsFiles)
}

func extractAPIsFromJS(jsContent, base string) []string {
	var apis []string
	for _, m := range reFetch.FindAllStringSubmatch(jsContent, -1) {
		if len(m) > 1 { apis = append(apis, m[1]) }
	}
	for _, m := range reAPI.FindAllStringSubmatch(jsContent, -1) {
		if len(m) > 1 { apis = append(apis, m[1]) }
	}
	for _, m := range reJSRoute.FindAllStringSubmatch(jsContent, -1) {
		if len(m) > 1 { apis = append(apis, m[1]) }
	}
	var fullAPIs []string
	for _, api := range apis {
		if full := resolveURL(base, api); full != "" { fullAPIs = append(fullAPIs, full) }
	}
	return uniqueStrings(fullAPIs)
}

func resolveURL(base, rel string) string {
	baseURL, err := url.Parse(base)
	if err != nil { return "" }
	relURL, err := url.Parse(rel)
	if err != nil { return "" }
	return baseURL.ResolveReference(relURL).String()
}

func extractAPIEndpoints(html string) []string { return extractAPIEndpointsEnhanced(html, nil) }

func extractAPIEndpointsEnhanced(html string, staticExts []string) []string {
	var endpoints []string
	for _, m := range reAPI.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			path := m[1]
			if staticExts != nil && containsString(staticExts, filepath.Ext(path)) { continue }
			endpoints = append(endpoints, path)
		}
	}
	for _, m := range reFetch.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			path := m[1]
			if staticExts != nil && containsString(staticExts, filepath.Ext(path)) { continue }
			endpoints = append(endpoints, path)
		}
	}
	return endpoints
}

func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range slice {
		if !seen[s] { seen[s] = true; result = append(result, s) }
	}
	return result
}

func containsString(slice []string, s string) bool {
	for _, v := range slice { if v == s { return true } }
	return false
}

func isAllDigits(s string) bool {
	for _, c := range s { if c < '0' || c > '9' { return false } }
	return true
}

func abs(x int) int { if x < 0 { return -x }; return x }

func hashString(s string) string {
	h := fnv.New32a()
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum32())
}

func getUAForTarget(target string) string {
	h := fnv.New32a()
	h.Write([]byte(target))
	return userAgents[h.Sum32()%uint32(len(userAgents))]
}

func logHigh(msg string, args ...interface{})   { log.Printf("\033[31m[高危] "+msg+"\033[0m", args...) }
func logMedium(msg string, args ...interface{}) { log.Printf("\033[33m[中危] "+msg+"\033[0m", args...) }
func logWarn(msg string, args ...interface{})   { log.Printf("\033[35m[警告] "+msg+"\033[0m", args...) }

func cleanDynamicContent(body []byte) []byte {
	body = reTimeClean.ReplaceAll(body, []byte("__TIMESTAMP__"))
	body = reRandClean.ReplaceAll(body, []byte("__RANDOM__"))
	return body
}
