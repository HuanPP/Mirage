//go:build linux

package syn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Check diagnoses sysctls, the actual negotiated kernel scale, and nft rules.
// The unmarked loopback probe needs no raw socket or CAP_NET_RAW.
func Check(ctx context.Context, c Config, w io.Writer) error {
	if err := c.Validate(); err != nil {
		return err
	}
	var failures []error
	var maxRmem uint64
	for _, key := range []string{"net.ipv4.tcp_rmem", "net.core.rmem_max", "net.ipv4.tcp_timestamps", "net.ipv4.tcp_sack", "net.ipv4.tcp_window_scaling"} {
		b, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
		if err != nil {
			fmt.Fprintf(w, "%s: unavailable (%v)\n", key, err)
			// Linux 6.1 does not expose this global sysctl in private netns.
			if key != "net.core.rmem_max" {
				failures = append(failures, err)
			}
			continue
		}
		fields := strings.Fields(string(b))
		if len(fields) == 0 {
			failures = append(failures, fmt.Errorf("empty sysctl %s", key))
			continue
		}
		v, err := strconv.ParseUint(fields[len(fields)-1], 10, 64)
		ok := err == nil && v == 1
		if key == "net.ipv4.tcp_rmem" || key == "net.core.rmem_max" {
			ok = err == nil && v >= 2097152 && v <= 4194303
			maxRmem = max(maxRmem, v)
		}
		fmt.Fprintf(w, "%s: %s requirement_met=%t\n", key, strings.TrimSpace(string(b)), ok)
		if !ok {
			failures = append(failures, fmt.Errorf("%s does not meet the profile requirement", key))
		}
	}
	if maxRmem > 0 {
		fmt.Fprintf(w, "sysctl_scale_estimate=%d (socket receive space and window clamp may affect this)\n", max(0, min(14, bits.Len64(maxRmem)-1-15)))
	}
	ws, enabled, err := observedScale(ctx)
	if err != nil {
		failures = append(failures, err)
		fmt.Fprintf(w, "observed_wscale: %v\n", err)
	} else {
		fmt.Fprintf(w, "observed_wscale=%d expected_wscale=6 scaling_negotiated=%t (unmarked loopback TCP_INFO; TCP_MAXSEG=1460)\n", ws, enabled)
		if ws != 6 || !enabled {
			failures = append(failures, fmt.Errorf("kernel window scale requires tuning"))
		}
	}
	if err := checkRules(ctx, c); err != nil {
		fmt.Fprintf(w, "nft rules: %v\n", err)
		failures = append(failures, err)
	} else {
		fmt.Fprintln(w, "nft rules: match configured mark, queue, bypass, hook, and IPv6 policy")
	}
	return errors.Join(failures...)
}

func observedScale(ctx context.Context) (uint8, bool, error) {
	control := func(_, _ string, raw syscall.RawConn) error {
		var inner error
		err := raw.Control(func(fd uintptr) { inner = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, 1460) })
		return errors.Join(err, inner)
	}
	lc := net.ListenConfig{Control: control}
	l, err := lc.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, false, err
	}
	defer l.Close()
	d := net.Dialer{Control: control, Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp4", l.Addr().String())
	if err != nil {
		return 0, false, err
	}
	defer conn.Close()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		return 0, false, err
	}
	var ws uint8
	var enabled bool
	var inner error
	err = raw.Control(func(fd uintptr) {
		info, e := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if e != nil {
			inner = e
			return
		}
		// x/sys TCPInfo omits the UAPI bitfields in byte 6. The syscall
		// fills that padding byte; decode its receive-scale nibble.
		value := *(*byte)(unsafe.Add(unsafe.Pointer(info), 6))
		var endian uint16 = 1
		if *(*byte)(unsafe.Pointer(&endian)) == 1 {
			ws = value >> 4
		} else {
			ws = value & 15
		}
		const tcpiOptWScale = 4 // Linux UAPI include/uapi/linux/tcp.h.
		enabled = info.Options&tcpiOptWScale != 0
	})
	return ws, enabled, errors.Join(err, inner)
}

func checkRules(ctx context.Context, c Config) error {
	b, err := nft(ctx, "", "-j", "list", "table", "inet", TableName)
	if err != nil {
		return err
	}
	return verifyRulesJSON(b, c)
}

func verifyRulesJSON(b []byte, c Config) error {
	var doc struct {
		NFTables []struct {
			Chain *struct {
				Family, Table, Name, Type, Hook, Policy string
				Prio                                    int
			} `json:"chain"`
			Rule *struct {
				Family, Table, Chain string
				Expr                 []map[string]any
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return err
	}
	chains, rules := 0, 0
	var actual [][]map[string]any
	for _, item := range doc.NFTables {
		if x := item.Chain; x != nil {
			chains++
			if x.Family != "inet" || x.Table != TableName || x.Name != "outbound" || x.Type != "filter" || x.Hook != "postrouting" || x.Prio != 110 || x.Policy != "accept" {
				return fmt.Errorf("unexpected nft chain")
			}
		}
		if x := item.Rule; x != nil {
			rules++
			if x.Family != "inet" || x.Table != TableName || x.Chain != "outbound" {
				return fmt.Errorf("unexpected nft rule location")
			}
			var expr []map[string]any
			for _, e := range x.Expr {
				if _, counter := e["counter"]; counter {
					continue
				}
				// nft can elide an explicit TCP l4proto dependency when TCP
				// flags already require it. JSON flags allow scalar or array.
				if m, ok := e["match"].(map[string]any); ok {
					if reflect.DeepEqual(m, map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "l4proto"}}, "right": "tcp"}) {
						continue
					}
				}
				if q, ok := e["queue"].(map[string]any); ok {
					if flag, ok := q["flags"].(string); ok {
						q["flags"] = []any{flag}
					}
				}
				expr = append(expr, e)
			}
			actual = append(actual, expr)
		}
	}
	var expected [][]map[string]any
	if c.SYN.Enabled {
		common := fmt.Sprintf(`{"match":{"op":"==","left":{"&":[{"payload":{"protocol":"tcp","field":"flags"}},["syn","ack"]]},"right":"syn"}},{"match":{"op":"==","left":{"meta":{"key":"mark"}},"right":%d}}`, c.Mark)
		v4 := fmt.Sprintf(`[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"protocol"}},"right":"tcp"}},%s,{"queue":{"num":%d,"flags":["bypass"]}}]`, common, c.SYN.QueueNum)
		var e []map[string]any
		if err := json.Unmarshal([]byte(v4), &e); err != nil {
			return err
		}
		expected = append(expected, e)
		if c.IPv6 == "block" {
			v6 := fmt.Sprintf(`[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv6"}},%s,{"drop":null}]`, common)
			var ipv6Expr []map[string]any
			if err := json.Unmarshal([]byte(v6), &ipv6Expr); err != nil {
				return err
			}
			expected = append(expected, ipv6Expr)
		}
	}
	if chains != 1 || rules != len(expected) || !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("nft rule expressions do not match config (observed %s)", b)
	}
	return nil
}
