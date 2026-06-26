package main

import "time"

type Config struct {
	Target          string
	SubDict         string
	DirDict         string
	Threads         int
	RateLimit       int
	Timeout         int
	RetryCount      int
	RetryWaitMin    int
	MaxDepth        int
	MaxResponseSize int64
	CacheTTL        int
	CacheFile       string
	PocOutputDir    string

	SubdomainOnly   bool
	DirBruteOnly    bool
	APIDiscoverOnly bool
	Recursive       bool
	Smart404        bool
	DeepJS          bool
	FilterStatic    bool
	StealthMode     bool
	EnableAuthCheck bool
	EnableIDOR      bool
	EnableMutate    bool
	CTLogEnabled    bool
	StableMode      bool

	EnableProxyRotation bool
	ProxyFile           string
	InsecureSkipVerify  bool
	JA3Enabled          bool
	ForceHTTP11         bool

	BaseDelayMin   float64
	BaseDelayMax   float64
	AdaptiveFactor float64
	DelayJitter    float64

	StaticExts []string
	MinBodyLen int
	MaxBodyLen int

	LowCookie      string
	LowHeaders     map[string]string
	AuthCheckPaths []string
	CustomHeaders  map[string]string

	EnableRendering bool
	EnablePortScan  bool
	ExtraPorts      string

	MaxScanDuration    time.Duration
	EnableHoneypotCheck bool
}

func DefaultConfig() Config {
	return Config{
		Threads:         20,
		RateLimit:       50,
		Timeout:         10,
		RetryCount:      2,
		RetryWaitMin:    200,
		MaxDepth:        3,
		MaxResponseSize: 2 * 1024 * 1024,
		CacheTTL:        300,
		Recursive:       true,
		Smart404:        true,
		DeepJS:          true,
		FilterStatic:    true,
		StealthMode:     false,
		EnableAuthCheck: true,
		EnableIDOR:      true,
		EnableMutate:    true,
		CTLogEnabled:    true,
		StableMode:      true,
		JA3Enabled:      true,
		ForceHTTP11:     false,
		BaseDelayMin:    0.5,
		BaseDelayMax:    1.5,
		AdaptiveFactor:  0.2,
		DelayJitter:     0.3,
		MinBodyLen:      50,
		MaxBodyLen:      500000,
		AuthCheckPaths:  []string{"/", "/api/v1/users", "/api/users", "/admin", "/dashboard"},
		StaticExts:      []string{".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz"},
		LowHeaders:      map[string]string{},
		CustomHeaders:   map[string]string{},
		EnableRendering: false,
		EnablePortScan:  false,
		ExtraPorts:      "",
		MaxScanDuration: 30 * time.Minute,
	}
}
