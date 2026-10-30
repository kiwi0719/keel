//go:build pprof

package main

import (
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
)

func init() {
	if addr := os.Getenv("KEEL_PPROF"); addr != "" {
		runtime.SetMutexProfileFraction(5)
		runtime.SetBlockProfileRate(100000)
		go http.ListenAndServe(addr, nil)
	}
}
