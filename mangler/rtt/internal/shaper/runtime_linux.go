//go:build linux

package shaper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"mirage/rtt/internal/config"
)

type Options struct {
	StateDir, PinDir, Samples string
	DefaultQdiscFile          string
	InstallQdisc, DryRun      bool
}
type state struct {
	Iface     string
	Plan      Plan
	ProgramID uint32
	Applied   int
}

// Ring-buffer events have no map value BTF for bpf2go to generate. This wire
// layout matches struct sample in bpf.c: 12-byte tuple, u32, u64, u64, s64.
type ackSample struct {
	Key                                    rttTuple
	Kind                                   uint32
	Now, Edt                               uint64
	Jitter                                 int64
	Ack, Seq, CPU, Flags                   uint32
	OriginalAck, Tsecr, OriginalTsecr, GSO uint32
	Priority, SkState                      uint32
}

func (o Options) statePath(iface string) string { return filepath.Join(o.StateDir, iface+".json") }
func (o Options) pins(iface string) string      { return filepath.Join(o.PinDir, iface) }
func command(w []string) (string, error) {
	if w[0] == "tc" {
		w = append([]string{"/usr/sbin/tc"}, w[1:]...)
	}
	b, e := exec.Command(w[0], w[1:]...).CombinedOutput()
	if e != nil {
		return string(b), fmt.Errorf("%s: %w: %s", ShellCommand(w), e, b)
	}
	return string(b), nil
}
func qdiscs(iface string) (string, error) {
	return command([]string{"tc", "qdisc", "show", "dev", iface})
}
func saveState(path string, s state) error {
	b, e := json.MarshalIndent(s, "", "  ")
	if e != nil {
		return e
	}
	tmp := path + ".tmp"
	if e = os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
func readState(path string) (state, error) {
	var s state
	b, e := os.ReadFile(path)
	if e == nil {
		e = json.Unmarshal(b, &s)
	}
	return s, e
}

func Install(c config.Config, o Options) (err error) {
	if _, e := os.Stat(o.statePath(c.RTT.Iface)); e == nil {
		return fmt.Errorf("already installed; run check or uninstall first")
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	before, e := qdiscs(c.RTT.Iface)
	if e != nil {
		return e
	}
	// Dry-run prints the authorized plan, including refusal when authorization is absent.
	p, e := MakePlan(c.RTT.Iface, before, true)
	if e != nil {
		return e
	}
	beforeJSON, e := command([]string{"tc", "-j", "qdisc", "show", "dev", c.RTT.Iface})
	if e != nil {
		return e
	}
	if e = p.ExactRollback(beforeJSON); e != nil {
		return e
	}
	link, e := netlink.LinkByName(c.RTT.Iface)
	if e != nil {
		return e
	}
	if p.Anonymous {
		path := o.DefaultQdiscFile
		if path == "" {
			path = "/proc/sys/net/core/default_qdisc"
		}
		defaultQdisc, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if e = p.DefaultRollback(c.RTT.Iface, beforeJSON, strings.TrimSpace(string(defaultQdisc)), link.Attrs().MTU); e != nil {
			return e
		}
	}
	attrs := netlink.FilterAttrs{LinkIndex: link.Attrs().Index, Parent: netlink.HANDLE_MIN_EGRESS, Priority: 4949, Protocol: unix.ETH_P_ALL, Handle: 1}
	filters, e := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if e != nil && !errors.Is(e, unix.ENOENT) && !errors.Is(e, unix.EINVAL) {
		return e
	}
	for _, f := range filters {
		if f.Attrs().Priority == 4949 {
			return fmt.Errorf("egress priority 4949 is occupied")
		}
	}
	fmt.Printf("Original qdiscs:\n%s", before)
	for _, w := range p.Commands {
		fmt.Println(ShellCommand(w))
	}
	fmt.Printf("Load embedded BPF with cilium/ebpf; pin maps and program under %s\n", o.pins(c.RTT.Iface))
	fmt.Printf("tc filter add dev %s egress protocol all pref 4949 handle 1 bpf direct-action pinned %s/program\n", c.RTT.Iface, o.pins(c.RTT.Iface))
	fmt.Printf("Rollback script %s/rtt-rollback.sh:\n%s", o.StateDir, p.Script())
	if !o.InstallQdisc && len(p.Rollback) > 0 {
		return fmt.Errorf("refusing qdisc changes without --install-qdisc; the plan above was not executed")
	}
	if p.Anonymous {
		return fmt.Errorf("refusing installation: anonymous qdiscs differ from the current kernel default (including MTU-derived quantum); exact rollback is unavailable")
	}
	if o.DryRun {
		return nil
	}
	if e = os.MkdirAll(o.StateDir, 0700); e != nil {
		return e
	}
	if e = os.MkdirAll(o.pins(c.RTT.Iface), 0700); e != nil {
		return e
	}
	s := state{Iface: c.RTT.Iface, Plan: p}
	if e = saveState(o.statePath(c.RTT.Iface), s); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(o.StateDir, "rtt-rollback.sh"), []byte(p.Script()), 0700); e != nil {
		return e
	}
	defer func() {
		if err != nil {
			if cleanup := Uninstall(c, o); cleanup != nil {
				err = errors.Join(err, fmt.Errorf("installation rollback: %w", cleanup))
			}
		}
	}()
	var objs rttObjects
	if e = loadRttObjects(&objs, nil); e != nil {
		return fmt.Errorf("load BPF: %w", e)
	}
	defer objs.Close()
	if e = seed(&objs, c); e != nil {
		return e
	}
	// A program array needs a userspace reference (a pin) after loader FDs close;
	// a reference from its calling BPF program alone does not retain its entries.
	for name, m := range map[string]*ebpf.Map{"configs": objs.Configs, "flows": objs.Flows, "normals": objs.Normals, "samples": objs.Samples, "telemetry": objs.Telemetry, "stages": objs.Stages} {
		if e = m.Pin(filepath.Join(o.pins(c.RTT.Iface), name)); e != nil {
			return e
		}
	}
	if e = objs.MirageRtt.Pin(filepath.Join(o.pins(c.RTT.Iface), "program")); e != nil {
		return e
	}
	info, e := objs.MirageRtt.Info()
	if e != nil {
		return e
	}
	id, _ := info.ID()
	s.ProgramID = uint32(id)
	if e = saveState(o.statePath(c.RTT.Iface), s); e != nil {
		return e
	}
	for i, w := range p.Commands {
		if _, e = command(w); e != nil {
			return e
		}
		s.Applied = i + 1
		if e = saveState(o.statePath(c.RTT.Iface), s); e != nil {
			return e
		}
	}
	f := &netlink.BpfFilter{FilterAttrs: attrs, Fd: objs.MirageRtt.FD(), Name: "mirage_rtt", DirectAction: true}
	if e = netlink.FilterAdd(f); e != nil {
		return e
	}
	return nil
}
func bpfConfig(c config.Config, base float64) rttConfig {
	// Reserve a burst interval at the lower delay bound. Userspace computes it
	// once rather than multiplying signed-arithmetic verifier branches in BPF.
	bound := c.RTT.Min
	if c.RTT.Jitter > 0 {
		bound = math.Max(bound, base-3*c.RTT.Jitter)
	}
	floor := bound + math.Min(c.RTT.Max, base+3*c.RTT.Jitter)/30
	if floor > c.RTT.Max {
		floor = c.RTT.Min
	}
	return rttConfig{Delay: uint64(base * 1e6), Minimum: uint64(c.RTT.Min * 1e6), Maximum: uint64(c.RTT.Max * 1e6), Floor: uint64(floor * 1e6), Sigma: int64(c.RTT.Jitter * 1e6), Gain: int64(math.Sqrt(1-c.RTT.Rho*c.RTT.Rho) * c.RTT.Jitter * 1e6), Rho: uint32(c.RTT.Rho * 65536), Enabled: boolUint(c.RTT.Enabled)}
}
func boolUint(v bool) uint32 {
	if v {
		return 1
	}
	return 0
}
func seed(o *rttObjects, c config.Config) error {
	for i, program := range []*ebpf.Program{o.RttRelease, o.RttSchedule, o.RttEmit} {
		if e := o.Stages.Put(uint32(i), program); e != nil {
			return e
		}
	}
	// Stratified normal quantiles eliminate finite-table mean/variance drift while
	// prandom selects independently from the table. No random math runs in BPF.
	rng := rand.New(rand.NewPCG(0x4d49, 0x727474))
	values := make([]int32, 4096)
	for i := range values {
		p := (float64(i) + .5) / 4096
		values[i] = int32(math.Sqrt2 * math.Erfinv(2*p-1) * 65536)
	}
	rng.Shuffle(len(values), func(i, j int) { values[i], values[j] = values[j], values[i] })
	for i, v := range values {
		if e := o.Normals.Put(uint32(i), v); e != nil {
			return e
		}
	}
	return o.Configs.Put(c.Mark, bpfConfig(c, c.Base()))
}
func Uninstall(c config.Config, o Options) error {
	s, e := readState(o.statePath(c.RTT.Iface))
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if s.Iface != c.RTT.Iface {
		return fmt.Errorf("state interface mismatch")
	}
	if o.DryRun {
		fmt.Printf("tc filter del dev %s egress pref 4949 handle 1 bpf\n%s", s.Iface, s.Plan.Script())
		return nil
	}
	link, e := netlink.LinkByName(s.Iface)
	if e != nil {
		return e
	}
	filters, e := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if e != nil && !errors.Is(e, unix.EINVAL) && !errors.Is(e, unix.ENOENT) {
		return e
	}
	for _, f := range filters {
		if f.Attrs().Priority == 4949 {
			b, ok := f.(*netlink.BpfFilter)
			if !ok || uint32(b.Id) != s.ProgramID || f.Attrs().Handle != 1 {
				return fmt.Errorf("refusing to delete foreign tc filter")
			}
			if e = netlink.FilterDel(f); e != nil {
				return e
			}
		}
	}
	// A clsact belongs to us only when we created it; preserve other users' filters.
	if s.Plan.CreatedClsact && s.Applied == len(s.Plan.Commands) {
		for _, parent := range []uint32{netlink.HANDLE_MIN_EGRESS, netlink.HANDLE_MIN_INGRESS} {
			fs, err := netlink.FilterList(link, parent)
			if err == nil && len(fs) > 0 {
				return fmt.Errorf("foreign filters now use our clsact; remove them before retrying uninstall")
			}
		}
		current, err := qdiscs(s.Iface)
		if err != nil {
			return err
		}
		if strings.Contains(current, "qdisc clsact ") {
			if _, e = command([]string{"tc", "qdisc", "del", "dev", s.Iface, "clsact"}); e != nil {
				return e
			}
		}
	}
	for _, w := range s.Plan.Rollback {
		if s.Applied == 0 {
			break
		}
		if _, e = command(w); e != nil {
			return e
		}
	}
	if e = os.RemoveAll(o.pins(s.Iface)); e != nil {
		return e
	}
	if e = os.Remove(o.statePath(s.Iface)); e != nil {
		return e
	}
	if e = os.Remove(filepath.Join(o.StateDir, "rtt-rollback.sh")); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	fmt.Println("Uninstalled; recorded qdisc layout restored")
	return nil
}
func Check(c config.Config, o Options) error {
	s, e := readState(o.statePath(c.RTT.Iface))
	if e != nil {
		return e
	}
	link, e := netlink.LinkByName(c.RTT.Iface)
	if e != nil {
		return e
	}
	fs, e := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if e != nil {
		return e
	}
	found := false
	for _, f := range fs {
		if b, ok := f.(*netlink.BpfFilter); ok && f.Attrs().Priority == 4949 && f.Attrs().Handle == 1 && uint32(b.Id) == s.ProgramID {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("owned BPF filter is absent")
	}
	q, e := qdiscs(c.RTT.Iface)
	if e != nil {
		return e
	}
	if e = validateFQ(q, c.RTT.Max); e != nil {
		return e
	}
	m, e := ebpf.LoadPinnedMap(filepath.Join(o.pins(c.RTT.Iface), "configs"), nil)
	if e != nil {
		return e
	}
	defer m.Close()
	var cfg rttConfig
	if e = m.Lookup(c.Mark, &cfg); e != nil {
		return e
	}
	fmt.Printf("OK iface=%s program_id=%d mark=%#x base_delay_ms=%.3f enabled=%d\n%s", c.RTT.Iface, s.ProgramID, c.Mark, float64(cfg.Delay)/1e6, cfg.Enabled, q)
	return nil
}
func Run(ctx context.Context, c config.Config, o Options) error {
	installed := false
	if _, e := os.Stat(o.statePath(c.RTT.Iface)); errors.Is(e, os.ErrNotExist) {
		if e = Install(c, o); e != nil {
			return e
		}
		installed = true
	}
	if installed {
		defer func() {
			if e := Uninstall(c, o); e != nil {
				log.Printf("cleanup failed: %v", e)
			}
		}()
	}
	if e := Check(c, o); e != nil {
		return e
	}
	m, e := ebpf.LoadPinnedMap(filepath.Join(o.pins(c.RTT.Iface), "configs"), nil)
	if e != nil {
		return e
	}
	defer m.Close()
	if o.Samples != "" {
		stop, e := recordSamples(c, o)
		if e != nil {
			return e
		}
		defer stop()
	}
	var estimator Estimator
	fallbackLogged := false
	update := func() error {
		base := c.Base()
		if c.RTT.Base == "auto" {
			samples, e := ClientRTTs(c.RTT.Client.Port)
			if e != nil {
				return fmt.Errorf("inet_diag: %w", e)
			}
			var ok bool
			base, ok = estimator.Update(time.Now(), samples, c.RTT.Default)
			if !ok && !fallbackLogged {
				log.Printf("No inbound RTT samples on port %d; fallback %.3fms", c.RTT.Client.Port, base)
				fallbackLogged = true
			}
			if ok {
				fallbackLogged = false
			}
		}
		base = math.Max(c.RTT.Min, math.Min(c.RTT.Max, base))
		return m.Put(c.Mark, bpfConfig(c, base))
	}
	if e = update(); e != nil {
		return e
	}
	log.Printf("Ready iface=%s mark=%#x", c.RTT.Iface, c.Mark)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if e = update(); e != nil {
				log.Printf("RTT update failed; retaining previous config: %v", e)
			}
		}
	}
}
func recordSamples(c config.Config, o Options) (func(), error) {
	m, e := ebpf.LoadPinnedMap(filepath.Join(o.pins(c.RTT.Iface), "samples"), nil)
	if e != nil {
		return nil, e
	}
	rd, e := ringbuf.NewReader(m)
	m.Close()
	if e != nil {
		return nil, e
	}
	file, e := os.Create(o.Samples)
	if e != nil {
		rd.Close()
		return nil, e
	}
	flag, e := ebpf.LoadPinnedMap(filepath.Join(o.pins(c.RTT.Iface), "telemetry"), nil)
	if e != nil {
		rd.Close()
		file.Close()
		return nil, e
	}
	if e = flag.Put(uint32(0), uint32(1)); e != nil {
		flag.Close()
		rd.Close()
		file.Close()
		return nil, e
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		enc := json.NewEncoder(file)
		for {
			r, e := rd.Read()
			if e != nil {
				return
			}
			var s ackSample
			if e = binary.Read(bytes.NewReader(r.RawSample), binary.NativeEndian, &s); e != nil {
				log.Printf("sample decode: %v", e)
				continue
			}
			if e = enc.Encode(s); e != nil {
				log.Printf("sample write: %v", e)
				return
			}
		}
	}()
	return func() {
		if e := flag.Put(uint32(0), uint32(0)); e != nil {
			log.Print(e)
		}
		flag.Close()
		rd.Close()
		<-done
		file.Close()
	}, nil
}

func validateFQ(q string, maxMS float64) error {
	count := 0
	for _, line := range strings.Split(q, "\n") {
		w := strings.Fields(line)
		if len(w) < 3 || w[1] == "clsact" || w[1] == "mq" {
			continue
		}
		if w[1] != "fq" {
			return fmt.Errorf("EDT requires fq on every transmit queue: %s", line)
		}
		count++
		horizon, e := time.ParseDuration(valueAfter(w, "horizon"))
		if e != nil || float64(horizon)/float64(time.Millisecond) <= maxMS {
			return fmt.Errorf("fq horizon must exceed max_delay_ms: %s", line)
		}
		limit, e := strconv.Atoi(strings.TrimSuffix(valueAfter(w, "flow_limit"), "p"))
		if e != nil {
			return e
		}
		if limit < 4096 {
			log.Printf("fq flow_limit=%d can drop bursts of delayed ACKs; recommended 4096", limit)
		}
	}
	if count == 0 {
		return fmt.Errorf("fq is absent")
	}
	return nil
}
