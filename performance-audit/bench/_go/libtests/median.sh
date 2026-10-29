#!/bin/sh
# usage: median.sh < go-test-bench-output ; prints median ns/op per benchmark name
awk '/^Benchmark/ { for (i=1;i<=NF;i++) if ($(i+1)=="ns/op") { v[$1]=v[$1]" "$i } }
END { for (k in v) { n=split(v[k],a," "); for(i=1;i<=n;i++)for(j=i+1;j<=n;j++)if(a[j]<a[i]){t=a[i];a[i]=a[j];a[j]=t}; m=(n%2)?a[(n+1)/2]:(a[n/2]+a[n/2+1])/2; printf "%-60s median %10.1f ns/op  (n=%d, min %s max %s)\n", k, m, n, a[1], a[n] } }' | sort
