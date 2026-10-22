//go:build anytls && vless && ss

package main

import "testing"

func TestExampleConfigs(t *testing.T) {
	for _, path := range []string{"../../examples/entry.json", "../../examples/exit.json"} {
		if _, err := loadConfig(path); err != nil {
			t.Error(err)
		}
	}
}
