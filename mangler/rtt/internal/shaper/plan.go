package shaper

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type Plan struct {
	Before        string     `json:"before"`
	BeforeJSON    string     `json:"before_json"`
	Commands      [][]string `json:"commands"`
	Rollback      [][]string `json:"rollback"`
	CreatedClsact bool       `json:"created_clsact"`
	Anonymous     bool       `json:"anonymous_handles"`
}

// Deleting the root reconstructs mq and anonymous leaves from the kernel's
// default_qdisc. Accept this rollback only for the complete, unmodified default
// layout. In particular, a custom anonymous leaf is not exactly recreatable.
func (p *Plan) DefaultRollback(iface, raw, defaultKind string, mtu int) error {
	if !p.Anonymous {
		return nil
	}
	var qs []struct {
		Kind, Handle, Parent string
		Root                 bool
		Options              map[string]any
	}
	if err := json.Unmarshal([]byte(raw), &qs); err != nil {
		return err
	}
	root, leaves := 0, 0
	rootHandle := ""
	defaults := `{"limit":10240,"flows":1024,"quantum":1514,"target":4999,"interval":99999,"memory_limit":33554432,"ecn":true,"drop_batch":64}`
	var options map[string]any
	_ = json.Unmarshal([]byte(defaults), &options)
	// fq_codel initializes quantum from psched_mtu (Ethernet MTU + 14).
	// A layout left over from a previous MTU is not the current default: deleting
	// its root would silently change quantum and cannot be promised as exact.
	options["quantum"] = mtu + 14
	parents := map[string]bool{}
	for _, q := range qs {
		if q.Kind == "clsact" {
			continue
		}
		if q.Root {
			if q.Kind != "mq" || len(q.Options) != 0 {
				return nil
			}
			root++
			rootHandle = q.Handle
			continue
		}
		major := strings.TrimSuffix(rootHandle, ":")
		if major == "0" {
			major = ""
		}
		if defaultKind != "fq_codel" || q.Kind != defaultKind || q.Handle != "0:" || !strings.HasPrefix(q.Parent, major+":") || !regexp.MustCompile(`^[1-9a-f][0-9a-f]*$`).MatchString(strings.TrimPrefix(q.Parent, major+":")) || parents[q.Parent] {
			return nil
		}
		got, _ := json.Marshal(q.Options)
		want, _ := json.Marshal(options)
		if string(got) != string(want) {
			return nil
		}
		parents[q.Parent] = true
		leaves++
	}
	if root == 1 && leaves > 0 {
		parentPrefix := rootHandle
		if parentPrefix == "0:" {
			parentPrefix = ":"
		}
		for i := 1; i <= leaves; i++ {
			if !parents[fmt.Sprintf("%s%x", parentPrefix, i)] {
				return nil
			}
		}
		p.Rollback = [][]string{{"tc", "qdisc", "del", "dev", iface, "root"}}
		if rootHandle == "0:" {
			// Linux 6.1 qdisc_lookup skips handle 0: even its mq classes cannot
			// be addressed by tc parent :N. Give mq an explicit handle while
			// keeping mq as root, then replace its leaves. Deleting this root
			// restores the original anonymous mq and default leaves exactly.
			commands := [][]string{{"tc", "qdisc", "replace", "dev", iface, "root", "handle", "4948:", "mq"}}
			for _, command := range p.Commands {
				w := append([]string{}, command...)
				for i := 1; i < len(w); i++ {
					if w[i-1] == "parent" {
						w[i] = "4948" + w[i]
					}
				}
				commands = append(commands, w)
			}
			p.Commands = commands
		}
		// Explicit mq roots (including veth, whose default is noqueue) can be
		// recreated with their original handle and fresh anonymous default leaves.
		if rootHandle != "0:" {
			p.Rollback = append(p.Rollback, []string{"tc", "qdisc", "replace", "dev", iface, "root", "handle", rootHandle, "mq"})
		}
		p.Anonymous = false
	}
	return nil
}

// tc's human-readable times round microseconds (4999us prints as 5ms).
// Replace fq_codel rollback arguments from its JSON dump to preserve precision.
func (p *Plan) ExactRollback(raw string) error {
	p.BeforeJSON = raw
	var qs []struct {
		Kind, Parent string
		Root         bool
		Options      map[string]json.RawMessage
	}
	if err := json.Unmarshal([]byte(raw), &qs); err != nil {
		return err
	}
	for i, w := range p.Rollback {
		if !contains(w, "fq_codel") {
			continue
		}
		parent := valueAfter(w, "parent")
		root := contains(w, "root")
		found := false
		for _, q := range qs {
			if q.Kind != "fq_codel" || q.Parent != parent || q.Root != root {
				continue
			}
			found = true
			at := 0
			for k, s := range w {
				if s == "fq_codel" {
					at = k + 1
					break
				}
			}
			out := append([]string{}, w[:at]...)
			keys := []struct{ key, unit string }{{"limit", ""}, {"flows", ""}, {"quantum", ""}, {"target", "us"}, {"interval", "us"}, {"memory_limit", "b"}, {"drop_batch", ""}, {"ce_threshold", "us"}}
			known := map[string]bool{"ecn": true}
			for _, k := range keys {
				known[k.key] = true
				if v, ok := q.Options[k.key]; ok {
					var n uint64
					if err := json.Unmarshal(v, &n); err != nil {
						return fmt.Errorf("invalid fq_codel %s: %w", k.key, err)
					}
					// sch_fq_codel stores CoDel times in 1024ns ticks and dumps
					// floor(ticks*1024/1000) microseconds. Sending dump+1 us
					// reconstructs the identical tick count; sending dump loses one.
					if k.unit == "us" {
						n++
					}
					out = append(out, k.key, fmt.Sprint(n)+k.unit)
				}
			}
			if v, ok := q.Options["ecn"]; ok {
				var b bool
				if err := json.Unmarshal(v, &b); err != nil {
					return err
				}
				if b {
					out = append(out, "ecn")
				} else {
					out = append(out, "noecn")
				}
			}
			for k := range q.Options {
				if !known[k] {
					return fmt.Errorf("cannot exactly restore unknown fq_codel option %s", k)
				}
			}
			p.Rollback[i] = out
		}
		if !found {
			return fmt.Errorf("no JSON counterpart for fq_codel rollback")
		}
	}
	return nil
}

var safeIface = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

// tc's textual dump carries units and all parameters of these supported qdiscs.
// Refuse unfamiliar layouts rather than promise an inexact restoration.
func MakePlan(iface, before string, allow bool) (Plan, error) {
	p := Plan{Before: before}
	if !safeIface.MatchString(iface) {
		return p, fmt.Errorf("invalid interface name")
	}
	var root []string
	var children [][]string
	hasClsact := false
	for _, line := range strings.Split(strings.TrimSpace(before), "\n") {
		w := strings.Fields(line)
		if len(w) < 3 {
			continue
		}
		if w[1] == "clsact" {
			hasClsact = true
			continue
		}
		if w[1] == "ingress" {
			return p, fmt.Errorf("existing ingress qdisc conflicts with clsact")
		}
		if contains(w, "root") {
			root = w
		} else if contains(w, "parent") {
			children = append(children, w)
		}
	}
	if len(root) == 0 {
		return p, fmt.Errorf("no root qdisc found")
	}
	if root[1] == "mq" {
		for _, w := range children {
			if w[1] == "fq" {
				continue
			}
			if !allow {
				return p, fmt.Errorf("refusing qdisc changes: pass --install-qdisc; current layout:\n%s", before)
			}
			restore, e := restoreCommand(iface, w)
			if e != nil {
				return p, e
			}
			parent := valueAfter(w, "parent")
			// sch_api.c ignores handle=0 default qdiscs during modification.
			// Recreating a leaf allocates a new nonzero handle. The printed
			// rollback restores parameters but cannot restore that anonymous ID;
			// real installation must refuse this layout to honor exact rollback.
			if w[2] == "0:" {
				p.Anonymous = true
			}
			p.Commands = append(p.Commands, fqCommand(iface, "parent", parent))
			p.Rollback = append(p.Rollback, restore)
		}
		if len(children) == 0 {
			return p, fmt.Errorf("mq root has no visible children")
		}
	} else if root[1] != "fq" {
		if !allow {
			return p, fmt.Errorf("refusing root qdisc change: pass --install-qdisc; current layout:\n%s", before)
		}
		if len(children) > 0 {
			return p, fmt.Errorf("unsupported classful root layout")
		}
		restore, e := restoreCommand(iface, root)
		if e != nil {
			return p, e
		}
		if root[2] == "0:" && root[1] != "noqueue" {
			p.Anonymous = true
		}
		p.Commands = append(p.Commands, fqCommand(iface, "root", ""))
		p.Rollback = append(p.Rollback, restore)
	}
	if !hasClsact {
		p.CreatedClsact = true
		p.Commands = append(p.Commands, []string{"tc", "qdisc", "add", "dev", iface, "clsact"})
	}
	return p, nil
}
func contains(w []string, s string) bool {
	for _, v := range w {
		if v == s {
			return true
		}
	}
	return false
}

func fqCommand(iface, position, parent string) []string {
	out := []string{"tc", "qdisc", "replace", "dev", iface, position}
	if parent != "" {
		out = append(out, parent)
	}
	// fq's default flow_limit=100 can drop a burst of EDT-held ACKs, causing
	// spurious TCP retransmits. Provision room for a real distant-client BDP.
	return append(out, "fq", "limit", "65536", "flow_limit", "4096", "horizon", "10s", "horizon_drop")
}
func valueAfter(w []string, s string) string {
	for i, v := range w {
		if v == s && i+1 < len(w) {
			return w[i+1]
		}
	}
	return ""
}
func restoreCommand(iface string, w []string) ([]string, error) {
	kind := w[1]
	if kind == "noqueue" {
		return []string{"tc", "qdisc", "del", "dev", iface, "root"}, nil
	}
	if kind != "fq_codel" && kind != "fq" && kind != "pfifo_fast" {
		return nil, fmt.Errorf("cannot exactly restore qdisc %s", kind)
	}
	out := []string{"tc", "qdisc", "replace", "dev", iface}
	i := 3
	if contains(w, "root") {
		out = append(out, "root")
		i = 4
	} else {
		out = append(out, "parent", valueAfter(w, "parent"))
		i = 5
	}
	if w[2] != "0:" {
		out = append(out, "handle", w[2])
	}
	out = append(out, kind)
	for i < len(w) {
		if w[i] == "refcnt" {
			i += 2
			continue
		}
		// pfifo_fast's bands/priomap are read-only defaults; replacing it restores them.
		if kind == "pfifo_fast" {
			break
		}
		out = append(out, w[i])
		i++
	}
	return out, nil
}
func ShellCommand(w []string) string {
	v := make([]string, len(w))
	for i, s := range w {
		v[i] = "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
	}
	return strings.Join(v, " ")
}
func (p Plan) Script() string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\nset -eu\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\nexport PATH\n")
	for _, w := range p.Rollback {
		b.WriteString(ShellCommand(w) + "\n")
	}
	return b.String()
}
