module github.com/kiwi0719/keel

go 1.26.10

replace github.com/anytls/sing-anytls => ./third_party/sing-anytls

require (
	github.com/anytls/sing-anytls v0.0.11
	github.com/coder/websocket v1.8.14
	github.com/metacubex/utls v1.8.4
	github.com/sagernet/sing v0.8.12-0.20260702081104-2ded2af32d3d
	github.com/sagernet/sing-shadowsocks v0.2.8
	github.com/sagernet/sing-vmess v0.2.8-0.20250909125414-3aed155119a1
	golang.org/x/crypto v0.58.0
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/gofrs/uuid/v5 v5.3.2 // indirect
	github.com/klauspost/compress v1.20.3 // indirect
	github.com/klauspost/cpuid/v2 v2.0.12 // indirect
	golang.org/x/exp v0.0.0-20240904232852-e7e105dedf7e // indirect
	golang.org/x/sys v0.49.0 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
)

replace github.com/sagernet/sing-shadowsocks => ./third_party/sing-shadowsocks

replace github.com/sagernet/sing-vmess => ./third_party/sing-vmess

replace github.com/metacubex/utls => ./third_party/utls
