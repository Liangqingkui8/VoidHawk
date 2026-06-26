package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type WAFSignature struct {
	Name string   `json:"name"`
	Keys []string `json:"keys"`
}

type WAFDetector struct {
	mu       sync.RWMutex
	sigs     []WAFSignature
	keywords []string
}

func NewWAFDetector() *WAFDetector {
	d := &WAFDetector{}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sigs = []WAFSignature{
		{Name: "cloudflare", Keys: []string{"cloudflare", "cf-ray", "__cfduid"}},
		{Name: "safedog", Keys: []string{"安全狗", "safedog"}},
		{Name: "yundun", Keys: []string{"阿里云盾", "yundun"}},
		{Name: "yunlock", Keys: []string{"云锁", "yunsuo"}},
		{Name: "dun", Keys: []string{"d盾", "d盾", "dun"}},
		{Name: "modsecurity", Keys: []string{"mod_security", "no-store, no-cache, must-revalidate", "modsecurity"}},
		{Name: "aws-waf", Keys: []string{"aws-waf", "awselb/2.0"}},
		{Name: "f5", Keys: []string{"big-ip", "f5"}},
		{Name: "fortinet", Keys: []string{"fortiwaf", "fortigate", "fortinet"}},
		{Name: "imperva", Keys: []string{"imperva", "incapsula", "x-iinfo"}},
		{Name: "akamai", Keys: []string{"akamai", "akamaighost"}},
		{Name: "barracuda", Keys: []string{"barracuda"}},
		{Name: "sucuri", Keys: []string{"sucuri", "sucuri_cloudproxy"}},
		{Name: "wordfence", Keys: []string{"wordfence"}},
		{Name: "knownsec", Keys: []string{"知道创宇", "ks-waf", "knownsec"}},
		{Name: "baidu-yunjiasu", Keys: []string{"baidu-yunjiasu", "yunjiasu"}},
		{Name: "huaweicloud", Keys: []string{"huaweicloud", "waf.huaweicloud"}},
		{Name: "tencent-ngwaf", Keys: []string{"tencent", "tl-waf"}},
	}
	d.rebuildKeywords()
	return d
}

func (d *WAFDetector) rebuildKeywords() {
	keywords := make([]string, 0)
	for _, sig := range d.sigs {
		for _, k := range sig.Keys {
			keywords = append(keywords, strings.ToLower(k))
		}
	}
	d.keywords = keywords
}

func (d *WAFDetector) UpdateFromURL(url string) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("[WAF] 更新签名失败: %v", err)
		return
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[WAF] 读取签名响应失败: %v", err)
		return
	}
	var sigs []WAFSignature
	if err := json.Unmarshal(data, &sigs); err != nil {
		log.Printf("[WAF] 签名JSON解析失败: %v", err)
		return
	}
	d.mu.Lock()
	d.sigs = append(d.sigs, sigs...)
	d.rebuildKeywords()
	d.mu.Unlock()
	log.Printf("[WAF] 签名更新成功，当前%d条规则", len(d.sigs))
	os.WriteFile("waf_cache.json", data, 0644)
}

func (d *WAFDetector) LoadCache(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var sigs []WAFSignature
	if err := json.Unmarshal(data, &sigs); err != nil {
		return
	}
	d.mu.Lock()
	d.sigs = append(d.sigs, sigs...)
	d.rebuildKeywords()
	d.mu.Unlock()
	log.Printf("[WAF] 加载%d条缓存签名", len(sigs))
}

func (d *WAFDetector) Keywords() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.keywords) == 0 {
		return nil
	}
	return d.keywords
}
