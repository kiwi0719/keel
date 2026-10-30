//go:build anytls && vless && ss

package main

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing-vmess/vless"
)

// BenchmarkConfigPush approximates what a node does for each config the
// master pushes (at least once a minute while users have traffic): parse the
// whole config, re-apply users and rebuild every inbound's user table.
func BenchmarkConfigPush(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			users := make([]UserConfig, n)
			for i := range users {
				users[i] = UserConfig{Name: fmt.Sprint("u", 1000+i), AnyTLSPassword: fmt.Sprintf("aB3dE6gH9jK2mN5pQ8sT1vW4yZ7b%04d", i),
					UUID: fmt.Sprintf("80cc6a3a-1514-4342-af5b-%012d", i), Flow: "xtls-rprx-vision", SSKey: "Dx4NiV8victJxIdnEHdBVA==",
					Period: "2026-10", QuotaBytes: 107374182400, UsedBase: 5368709120, UsedSelf: 123456789}
			}
			content, _ := json.Marshal(Config{Users: users})
			reg := newRegistry("")
			at, err := anytls.NewService(anytls.ServiceConfig{PaddingScheme: padding.DefaultPaddingScheme, Handler: &handler{users: reg}, Logger: stdLogger{}})
			if err != nil {
				b.Fatal(err)
			}
			ss, err2 := shadowaead_2022.NewMultiServiceWithPassword[string]("2022-blake3-aes-128-gcm", "aMACsktAq3rW3WoYP8aPbA==", 180, ssHandler{&handler{users: reg}}, time.Now)
			if err2 != nil {
				b.Fatal(err2)
			}
			b.ReportMetric(float64(len(content)), "config-bytes")
			for b.Loop() {
				c, err := parseConfig(content, false)
				if err != nil {
					b.Fatal(err)
				}
				reg.apply(c.Users)
				active := reg.active()
				var al []anytls.User
				var names, uuids, flows, keys []string
				for _, u := range active {
					al = append(al, anytls.User{Name: u.Name, Password: u.AnyTLSPassword})
					names, uuids, flows, keys = append(names, u.Name), append(uuids, u.UUID), append(flows, u.Flow), append(keys, u.SSKey)
				}
				at.UpdateUsers(al)
				v := vless.NewService[string](stdLogger{}, nil)
				v.UpdateUsers(names, uuids, flows)
				if err := ss.UpdateUsersWithPasswords(names, keys); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestPerUserMemory: heap held per configured user across the registry and
// the three protocol services' user tables.
func TestPerUserMemory(t *testing.T) {
	for _, n := range []int{1000, 5000} {
		users := make([]UserConfig, n)
		for i := range users {
			users[i] = UserConfig{Name: fmt.Sprint("u", 1000+i), AnyTLSPassword: fmt.Sprintf("aB3dE6gH9jK2mN5pQ8sT1vW4yZ7b%04d", i),
				UUID: fmt.Sprintf("80cc6a3a-1514-4342-af5b-%012d", i), Flow: "xtls-rprx-vision", SSKey: "Dx4NiV8victJxIdnEHdBVA==",
				Period: "2026-10", QuotaBytes: 107374182400}
		}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		reg := newRegistry("")
		reg.apply(users)
		at, _ := anytls.NewService(anytls.ServiceConfig{PaddingScheme: padding.DefaultPaddingScheme, Handler: &handler{users: reg}, Logger: stdLogger{}})
		ss, _ := shadowaead_2022.NewMultiServiceWithPassword[string]("2022-blake3-aes-128-gcm", "aMACsktAq3rW3WoYP8aPbA==", 180, ssHandler{&handler{users: reg}}, time.Now)
		v := vless.NewService[string](stdLogger{}, nil)
		var al []anytls.User
		var names, uuids, flows, keys []string
		for _, u := range reg.active() {
			al = append(al, anytls.User{Name: u.Name, Password: u.AnyTLSPassword})
			names, uuids, flows, keys = append(names, u.Name), append(uuids, u.UUID), append(flows, u.Flow), append(keys, u.SSKey)
		}
		at.UpdateUsers(al)
		v.UpdateUsers(names, uuids, flows)
		ss.UpdateUsersWithPasswords(names, keys)
		al, names, uuids, flows, keys = nil, nil, nil, nil, nil
		runtime.GC()
		runtime.ReadMemStats(&after)
		t.Logf("users=%d heap=%.1f MB (%.0f B/user)", n, float64(after.HeapAlloc-before.HeapAlloc)/1e6, float64(after.HeapAlloc-before.HeapAlloc)/float64(n))
		runtime.KeepAlive(reg)
		runtime.KeepAlive(at)
		runtime.KeepAlive(ss)
		runtime.KeepAlive(v)
	}
}
