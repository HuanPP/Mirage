//go:build linux

package shaper

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
	"mirage/rtt/internal/config"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestKernelSemantics(t *testing.T) {
	if os.Getenv("MIRRTT_KERNEL_TEST") != "1" {
		t.Skip("set MIRRTT_KERNEL_TEST=1 with BPF/NET_ADMIN capabilities")
	}
	var objs rttObjects
	if e := loadRttObjects(&objs, &ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 16 << 20}}); e != nil {
		var verifier *ebpf.VerifierError
		if errors.As(e, &verifier) {
			t.Fatalf("%+v", verifier)
		}
		t.Fatal(e)
	}
	defer objs.Close()
	var c config.Config
	c.Mark = 0x4d49
	c.RTT.Enabled = true
	c.RTT.Base = "160"
	c.RTT.Max = 600
	if e := seed(&objs, c); e != nil {
		t.Fatal(e)
	}
	packet := func(flags byte, payload int) []byte {
		b := make([]byte, 54+payload)
		b[12] = 8
		b[14] = 0x45
		binary.BigEndian.PutUint16(b[16:], uint16(40+payload))
		b[23] = 6
		b[26] = 10
		b[29] = 1
		b[30] = 10
		b[33] = 2
		binary.BigEndian.PutUint16(b[34:], 43210)
		binary.BigEndian.PutUint16(b[36:], 443)
		b[46] = 0x50
		b[47] = flags
		return b
	}
	run := func(b []byte, mark uint32, stamp uint64) uint64 {
		t.Helper()
		ctx := make([]byte, 192)
		binary.NativeEndian.PutUint32(ctx[8:], mark)
		binary.NativeEndian.PutUint64(ctx[152:], stamp)
		out := make([]byte, 192)
		data := make([]byte, len(b))
		_, e := objs.MirageRtt.Run(&ebpf.RunOptions{Data: b, DataOut: data, Context: ctx, ContextOut: out})
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(data, b) {
			t.Fatal("packet bytes changed")
		}
		return binary.NativeEndian.Uint64(out[152:])
	}
	if v := run(packet(2, 0), 0, 123); v != 123 {
		t.Fatal("unmarked timestamp changed", v)
	}
	v6 := packet(2, 0)
	v6[12] = 0x86
	v6[13] = 0xdd
	if v := run(v6, c.Mark, 456); v != 456 {
		t.Fatal("IPv6 timestamp changed", v)
	}
	if v := run(packet(2, 0), c.Mark, 789); v != 789 {
		t.Fatal("SYN delayed", v)
	}
	c.RTT.Base = "80"
	if e := objs.Configs.Put(c.Mark, bpfConfig(c, 80)); e != nil {
		t.Fatal(e)
	}
	ack := run(packet(0x10, 0), c.Mark, 0)
	data := run(packet(0x18, 32), c.Mark, 0)
	if data != ack+1 {
		t.Fatal("handshake payload escaped barrier", data, ack)
	}
	key := rttTuple{Saddr: binary.NativeEndian.Uint32([]byte{10, 0, 0, 1}), Daddr: binary.NativeEndian.Uint32([]byte{10, 0, 0, 2}), Sport: binary.NativeEndian.Uint16([]byte{0xa8, 0xca}), Dport: binary.NativeEndian.Uint16([]byte{1, 0xbb})}
	var flow rttFlow
	if e := objs.Flows.Lookup(key, &flow); e != nil {
		t.Fatal(e)
	}
	if flow.Cfg.Delay != 160e6 || flow.Barrier-flow.Handshake != 160e6 {
		t.Fatal("flow snapshot changed", flow)
	}
	var now unix.Timespec
	if e := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); e != nil {
		t.Fatal(e)
	}
	flow.Handshake = uint64(now.Nano() - int64(300*time.Millisecond))
	flow.Barrier = 0
	flow.LastAck = 0
	flow.LastData = 0
	if e := objs.Flows.Put(key, flow); e != nil {
		t.Fatal(e)
	}
	if stamp := run(packet(0x18, 32), c.Mark, 37); stamp < uint64(now.Nano()) || stamp > uint64(now.Nano()+20e6) {
		t.Fatal("established data delayed", stamp)
	}
	stamp := run(packet(0x10, 0), c.Mark, 0)
	if delta := int64(stamp) - now.Nano(); delta < 160e6 || delta > 180e6 {
		t.Fatal("ACK delay incorrect", delta)
	}
	if e := objs.Flows.Lookup(key, &flow); e != nil {
		t.Fatal(e)
	}
	flow.LastAck = stamp + 100e6
	if e := objs.Flows.Put(key, flow); e != nil {
		t.Fatal(e)
	}
	previous := flow.LastAck
	for _, flags := range []byte{0x10, 0x50, 0x90} {
		next := run(packet(flags, 0), c.Mark, 0)
		if next != previous+1 {
			t.Fatal("ACK/ECE/CWR order not monotonic", flags, next, previous)
		}
		previous = next
	}
	// Repeated SYN keeps the first snapshot; a reused tuple gets the new base.
	run(packet(2, 0), c.Mark, 0)
	if e := objs.Flows.Lookup(key, &flow); e != nil {
		t.Fatal(e)
	}
	if flow.Cfg.Delay != 160e6 {
		t.Fatal("SYN retransmission reset snapshot")
	}
	newSyn := packet(2, 0)
	binary.BigEndian.PutUint32(newSyn[38:], 12345)
	run(newSyn, c.Mark, 0)
	if e := objs.Flows.Lookup(key, &flow); e != nil {
		t.Fatal(e)
	}
	if flow.Cfg.Delay != 80e6 || flow.Handshake != 0 {
		t.Fatal("reused tuple not reset", flow)
	}
	run(packet(0x14, 0), c.Mark, 0)
	if e := objs.Flows.Lookup(key, &flow); !errors.Is(e, ebpf.ErrKeyNotExist) {
		t.Fatal("RST did not expire flow", e)
	}
	t.Log("verifier, mark/IPv6 bypass, immutable SYN snapshot, handshake payload barrier, data bypass, monotonic ACKs and RST cleanup passed")
}

func TestRequiredCapabilities(t *testing.T) {
	if os.Getenv("MIRRTT_KERNEL_TEST") != "1" {
		t.Skip("privileged capability check")
	}
	if os.Getenv("MIRRTT_CAP_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRequiredCapabilities$", "-test.v")
		cmd.Env = append(os.Environ(), "MIRRTT_CAP_CHILD=1")
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("%v: %s", e, out)
		}
		t.Log(string(out))
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	caps := [2]unix.CapUserData{{Effective: 1 << unix.CAP_NET_ADMIN, Permitted: 1 << unix.CAP_NET_ADMIN}, {Effective: 1 << (unix.CAP_BPF - 32), Permitted: 1 << (unix.CAP_BPF - 32)}}
	if e := unix.Capset(&header, &caps[0]); e != nil {
		t.Fatal(e)
	}
	var actual [2]unix.CapUserData
	if e := unix.Capget(&header, &actual[0]); e != nil {
		t.Fatal(e)
	}
	if actual != caps {
		t.Fatal(actual)
	}
	var objs rttObjects
	if e := loadRttObjects(&objs, &ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 16 << 20}}); e != nil {
		var verifier *ebpf.VerifierError
		if errors.As(e, &verifier) {
			t.Fatalf("%+v", verifier)
		}
		t.Fatal(e)
	}
	objs.Close()
	t.Log("BPF loads with only CAP_BPF + CAP_NET_ADMIN; CAP_PERFMON not required")
}
