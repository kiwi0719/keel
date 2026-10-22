//go:build vless && !with_utls

package main

// VLESS Vision only recognizes Reality connections when sing-vmess is built
// with the with_utls tag. Build with: -tags vless,with_utls (see Makefile).
var _ = vless_needs_the_with_utls_build_tag
