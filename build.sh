#!/bin/bash
# VoidHawk 跨平台构建脚本
# 用法: ./build.sh [版本号]

VERSION=${1:-dev}
OUTDIR="release"

mkdir -p $OUTDIR

echo "=== VoidHawk $VERSION 多平台构建 ==="

platforms=(
  "windows/amd64"
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
)

for p in "${platforms[@]}"; do
  GOOS=${p%/*}
  GOARCH=${p#*/}
  ext=""
  if [ "$GOOS" = "windows" ]; then ext=".exe"; fi
  name="voidhawk_${VERSION}_${GOOS}_${GOARCH}${ext}"

  echo "编译 $name..."
  GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o "$OUTDIR/$name" .
done

echo "=== 构建完成 ==="
ls -lh $OUTDIR/
