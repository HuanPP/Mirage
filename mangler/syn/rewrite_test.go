package syn

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Option areas are verbatim from /tmp/mirage_common.txt. Variable packet fields
// use a fixed fixture; checksum constants were calculated independently.
const nativeHex = "4500003cabb8400040067b010a0000010a0000029c4000501234567800000000a002ff282bba00000204058c0402080a010203040000000001030307"
const macHex = "4500004000004000400626b60a0000010a0000029c4000501234567800000000b002ffff19b60000020405b4010303070101080a010203040000000004020000"

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func validSum(data []byte) bool {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(data[i]) << 8
		if i+1 < len(data) {
			sum += uint32(data[i+1])
		}
	}
	for sum > 65535 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return sum == 65535
}

func assertChecksums(t *testing.T, p []byte) {
	t.Helper()
	if !validSum(p[:20]) {
		t.Fatal("invalid IP checksum")
	}
	ps := append([]byte{}, p[12:20]...)
	ps = append(ps, 0, 6, byte((len(p)-20)>>8), byte(len(p)-20))
	ps = append(ps, p[20:]...)
	if !validSum(ps) {
		t.Fatal("invalid TCP checksum")
	}
}

func TestGolden(t *testing.T) {
	for _, vector := range []struct{ name, native, mac string }{
		{"native_scale7", nativeHex, macHex},
		{"tuned_scale6",
			"4500003cabb8400040067b010a0000010a0000029c4000501234567800000000a002ff282bbb00000204058c0402080a010203040000000001030306",
			"4500004000004000400626b60a0000010a0000029c4000501234567800000000b002ffff19b70000020405b4010303060101080a010203040000000004020000"},
	} {
		t.Run(vector.name, func(t *testing.T) {
			in := decode(t, vector.native)
			assertChecksums(t, in)
			saved := append([]byte{}, in...)
			out, changed, err := Rewrite(in, MacOS(1460))
			if err != nil || !changed {
				t.Fatalf("changed=%t err=%v", changed, err)
			}
			if !bytes.Equal(out, decode(t, vector.mac)) {
				t.Fatalf("got %x", out)
			}
			if !bytes.Equal(saved, in) {
				t.Fatal("input mutated")
			}
			assertChecksums(t, out)
			if out[47] != in[59] {
				t.Fatal("kernel scale was altered")
			}
		})
	}
}

func TestScaleTimestampAndOffload(t *testing.T) {
	for _, scale := range []byte{0, 6, 7, 14} {
		in := decode(t, nativeHex)
		in[59] = scale
		in[1], in[8] = 0x28, 49
		copy(in[52:56], []byte{1, 2, 3, 4}) // TS echo must become zero.
		copy(in[10:12], []byte{0, 0})
		copy(in[36:38], []byte{0x14, 0x28}) // arbitrary partial checksum seed.
		out, changed, err := Rewrite(in, MacOS(1440))
		if err != nil || !changed {
			t.Fatal(changed, err)
		}
		if out[47] != scale || binary.BigEndian.Uint16(out[42:44]) != 1440 {
			t.Fatal("scale/MSS")
		}
		if out[1] != in[1] || out[8] != in[8] || !bytes.Equal(out[6:8], in[6:8]) {
			t.Fatal("TOS/TTL/DF altered")
		}
		if !bytes.Equal(out[52:56], in[48:52]) || !bytes.Equal(out[56:60], make([]byte, 4)) {
			t.Fatal("timestamp")
		}
		assertChecksums(t, out)
	}
}

func TestPassThrough(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"syn_ack":         func(p []byte) []byte { p[33] = 0x12; return p },
		"ack":             func(p []byte) []byte { p[33] = 0x10; return p },
		"tfo_data":        func(p []byte) []byte { p = append(p, 0x41); p[3]++; return p },
		"ip_options":      func(p []byte) []byte { p[0] = 0x46; return p },
		"unknown_option":  func(p []byte) []byte { p[40] = 30; return p },
		"tfo_cookie":      func(p []byte) []byte { p[40] = 34; return p },
		"non_tcp":         func(p []byte) []byte { p[9] = 17; return p },
		"ipv6":            func(p []byte) []byte { p[0] = 0x60; return p },
		"fragment":        func(p []byte) []byte { p[6] |= 0x20; return p },
		"fragment_offset": func(p []byte) []byte { p[7] = 1; return p },
		"missing_ws":      func(p []byte) []byte { copy(p[57:60], []byte{1, 1, 1}); return p },
		"missing_ts": func(p []byte) []byte {
			for i := 46; i < 56; i++ {
				p[i] = 1
			}
			p[46], p[47] = 1, 1
			p[44], p[45] = 1, 1
			return p
		},
		"duplicate_ws": func(p []byte) []byte { copy(p[40:44], []byte{3, 3, 7, 1}); return p },
		"eol":          func(p []byte) []byte { p[56] = 0; return p },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			in := alter(decode(t, nativeHex))
			out, changed, err := Rewrite(in, MacOS(1460))
			if err != nil || changed || !bytes.Equal(in, out) {
				t.Fatal(changed, err)
			}
		})
	}
}

func TestMalformed(t *testing.T) {
	for _, p := range [][]byte{nil, {0x45}, decode(t, nativeHex)[:30]} {
		out, changed, err := Rewrite(p, MacOS(1460))
		if err == nil || changed || !bytes.Equal(p, out) {
			t.Fatal("not a safe malformed pass-through")
		}
	}
	for _, position := range []int{3, 32, 41, 59} {
		p := decode(t, nativeHex)
		p[position] = 255
		out, changed, err := Rewrite(p, MacOS(1460))
		if err == nil || changed || !bytes.Equal(p, out) {
			t.Fatal(position, changed, err)
		}
	}
}

func FuzzRewrite(f *testing.F) {
	b, _ := hex.DecodeString(nativeHex)
	f.Add(b)
	f.Fuzz(func(t *testing.T, in []byte) {
		saved := append([]byte{}, in...)
		out, changed, err := Rewrite(in, MacOS(1460))
		if !bytes.Equal(saved, in) {
			t.Fatal("mutated input")
		}
		if changed {
			if err != nil || len(out) != 64 || out[32]>>4 != 11 {
				t.Fatal("bad rewrite")
			}
			assertChecksums(t, out)
		} else if !bytes.Equal(out, in) {
			t.Fatal("modified pass-through")
		}
	})
}

func TestConfigAndRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("mark: 0x12345\nipv6: passthrough\nsyn:\n  mss: 1440\nrtt:\n  arbitrary: ignored\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(path)
	if err != nil || c.Mark != 0x12345 || c.SYN.MSS != 1440 || c.SYN.QueueNum != 4949 {
		t.Fatal(c, err)
	}
	rules, err := Rules(c)
	if err != nil || !bytes.Contains([]byte(rules), []byte("queue num 4949 bypass")) || bytes.Contains([]byte(rules), []byte(" drop")) {
		t.Fatal(rules, err)
	}
	c.Mark = 0
	if c.Validate() == nil {
		t.Fatal("zero mark accepted")
	}
}
