package shaper

// Generation runs on Linux; the embedded bpfel object serves amd64 and arm64.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -target bpfel -cc clang -cflags "-O2 -g -Wall -Werror -I/usr/include/x86_64-linux-gnu" rtt bpf.c
