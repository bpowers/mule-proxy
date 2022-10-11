mule-proxy: hybrid Go + eBPF L4 proxy
=====================================

Mule attempts to provide the best of both worlds:
* full expressivity of Go for connection establishment (and rejection decisions)
* pure kernel-space proxying for established connections using the eBPF sockhash infrastructure

## Performance:

These benchmarks establish a TLS connection over the loopback interface and performs HTTP requests over the established connection:

```
cpu: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
BenchmarkNewConnBaseline-8       	  102624	     58409 ns/op	    4861 B/op	      60 allocs/op
BenchmarkNewConnMule-8           	   86451	     69386 ns/op	    4861 B/op	      60 allocs/op
BenchmarkNewConnGo-8             	   72558	     85488 ns/op	    4860 B/op	      60 allocs/op
```

On Intel systems (with a [kernel patch applied](https://github.com/bpowers/linux/commit/f14e03801e4081e0901698cddf2e2270d7445a72) to reduce the added latency of eBPF redirects from ~15 microseconds to ~10 microseconds),
proxying a TLS connection with a naive Go L4 Proxy incurs a 40% overhead - mule reduces this overhead to 16%.
[Cilium has a blog post describing a (more complicated and full featured) similar L4 proxy](https://cilium.io/blog/2022/04/12/cilium-standalone-L4LB-XDP/) suggesting an eBPF-based approach has the potential for significant CPU reduction over a userspace (like haproxy) or IPVS-based implementation.
