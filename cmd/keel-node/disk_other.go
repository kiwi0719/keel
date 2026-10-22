//go:build !unix

package main

func diskUsage(string) (total, used uint64) { return 0, 0 }
