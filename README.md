# 🦅 VoidHawk

![build](https://github.com/Liangqingkui8/VoidHawk/actions/workflows/build.yml/badge.svg)

**你站得再高，也躲不过这只鹰。**

VoidHawk 是一个看见目标就想把它翻个底朝天的 Web 信息收集工具。子域名、目录、API、鉴权漏洞、IDOR、绕过姿势，它全干，而且不挑食。

---

## 🚀 安装

```bash
git clone https://github.com/Liangqingkui8/VoidHawk
cd VoidHawk
go build -o voidhawk .
```

需要 Go 1.21+。别的不用装，除了 Chromium（如果你要用 JS 渲染的话）。

也可以去 [Releases](https://github.com/Liangqingkui8/VoidHawk/releases) 页面直接下载编译好的 exe。

**跨平台编译（在 Windows 上编译 Linux/Mac 版）：**

```bash
# Linux 64位
GOOS=linux GOARCH=amd64 go build -o voidhawk .

# Mac Intel
GOOS=darwin GOARCH=amd64 go build -o voidhawk .

# Mac M1/M2
GOOS=darwin GOARCH=arm64 go build -o voidhawk .

# 或者用一键脚本
chmod +x build.sh
./build.sh v1.0.0
```

---

## 🎯 快速上手

```bash
# 全量扫描（自带字典，clone 即用）
voidhawk -target example.com -no-ctlog

# 只看开了哪些门
voidhawk -target https://target.com -port-scan -no-ctlog

# 带着 Cookie 测鉴权
voidhawk -target https://target.com -cookie "session=abc123"

# 隐身模式——WAF 最好别注意到你
voidhawk -target https://target.com -stealth -rate 10 -threads 5

# 带浏览器渲染（需要本地有 Chromium）
voidhawk -target https://target.com -render

# 蜜罐检测——看看对面是不是在演你
voidhawk -target https://target.com -detect-honeypot
```

**常用参数：**

| 参数 | 作用 | 默认 |
|------|------|------|
| `-target` | 目标 URL 或域名（必填） | — |
| `-threads` | 并发数 | 20 |
| `-rate` | 每秒请求数 | 50 |
| `-cookie` | 带 Cookie 测鉴权 | — |
| `-stealth` | 隐身模式 | false |
| `-port-scan` | 扫常见 Web 端口 | false |
| `-render` | Chromium 动态渲染 | false |
| `-detect-honeypot` | 蜜罐检测 | false |
| `-subonly` / `-dironly` / `-apionly` | 单项模式 | false |

全参数请跑 `voidhawk.exe -h`。

---

## ⚔️ 它能干的事

- **子域名收集** — 字典爆破 + crt.sh 证书透明日志，泛解析自动过滤
- **目录爆破** — BFS 递归，Smart404 去噪，缓存增量扫描（第二次开始快十倍）
- **API 发现** — 静态 JS 分析 + Chromium 动态渲染，藏再深的接口也得现原形
- **CMS 识别** — WordPress / ThinkPHP / Laravel / Discuz，一眼看出对面穿什么裤衩
- **端口扫描** — 常见 Web 端口，轻量不扰民
- **鉴权检测** — 未授权访问 / 越权 / IDOR，Cookie 一挂自动扫
- **绕过测试** — HTTP 方法变异、路径混淆、伪造请求头，总有一个姿势能进门
- **隐身模式** — 每次请求随机切换 Chrome/Firefox/Safari 浏览器画像，JA3 TLS 指纹随机化，UA 随机轮换，自适应降速，代理轮换，WAF 看了想骂娘
- **蜜罐检测** — 点一下就知道对面是不是在钓鱼
- **增量扫描** — 今天扫了明天再扫，只出新结果

---

## 📂 字典

仓库自带了 `subdomains.txt`（72条常用子域名）和 `directories.txt`（85条常见路径），clone 下来直接用。

想扫得更全可以去嫖 [SecLists](https://github.com/danielmiessler/SecLists) 替换掉自带的。

---

## 🤖 自动构建

每次 push 到 main 分支，GitHub Actions 自动编译 5 个平台的版本：

- Windows amd64
- Linux amd64 / arm64
- macOS amd64 / arm64

打 Release 时，编译产物自动上传到 Release 页面，可以直接下载。

---

## 📦 输出

- `result.json` — 全量扫描结果
- `pocs/` — 漏洞 PoC 文件，curl 命令直接复制就能复现

---

## ⚠️ 友好提醒

这工具是用来做**授权的安全测试**的。拿去搞未授权的站，出了事自己扛。

法律面前人人平等，你我也不例外。

---

## 📜 协议

MIT License

你可以随便用、随便改、随便发，甚至拿它赚钱——只要保留原作者的版权声明就行。

别拿它干坏事然后说是别人教你的，成年人了，自己的枪自己扛。
