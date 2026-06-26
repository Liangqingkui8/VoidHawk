# VoidHawk

Go写的Web信息收集+鉴权检测工具。子域名/目录爆破/API发现/IDOR/越权绕过一体化。

## 安装

```bash
git clone https://github.com/你的用户名/VoidHawk
cd VoidHawk
go build -o voidhawk.exe .
```

需要Go 1.21+。

## 快速使用

```bash
# 基础扫描（需要字典文件）
voidhawk.exe -target example.com -sub subdomains.txt -dir directories.txt

# 只扫端口
voidhawk.exe -target example.com -port-scan -no-ctlog

# 带Cookie测鉴权
voidhawk.exe -target https://目标.com -cookie "session=abc123" -no-ctlog

# 隐身模式（降速+JA3随机化）
voidhawk.exe -target https://目标.com -stealth -rate 10 -threads 5

# JS渲染分析（需要Chromium）
voidhawk.exe -target https://目标.com -render
```

## 功能

- 子域名收集（字典+crt.sh证书透明度）
- 目录爆破（BFS递归，Smart404去噪，缓存增量扫描）
- API发现（静态JS分析+Chromium动态渲染）
- CMS指纹识别（WordPress/ThinkPHP/Laravel等）
- 端口扫描
- 鉴权检测（未授权/越权/IDOR）
- 鉴权绕过测试（HTTP方法/路径变异/请求头）
- JA3指纹随机化（隐身模式）
- 自适应限速+代理轮换
- 蜜罐轻量检测
- 输出结果缓存，支持增量扫描

## 字典

需要自备字典文件放到exe同目录：
- `subdomains.txt` — 子域名爆破
- `directories.txt` — 目录爆破

推荐：[SecLists](https://github.com/danielmiessler/SecLists)

## 输出

结果默认输出到 `result.json`，PoC文件输出到 `pocs/` 目录。

## 协议

你写的，你说了算。
