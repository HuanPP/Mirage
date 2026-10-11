// Package syn reshapes marked IPv4 TCP SYNs without modifying kernel TCP state.
package syn

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Profile describes the built-in wire template. ExpectedWScale is diagnostic;
// Rewrite always retains the scale negotiated by the kernel.
type Profile struct {
	Name           string
	Window         uint16
	MSS            uint16
	ExpectedWScale uint8
	OptionLayout   string
	IPIDPolicy     string
}

// MacOS returns the macOS 15 template from the captured reference.
func MacOS(mss uint16) Profile {
	return Profile{"macos", 65535, mss, 6, "MSS,NOP,WS,NOP,NOP,TS,SACK_PERM,EOL,0", "zero"}
}

func (p Profile) validate() error {
	if p != MacOS(p.MSS) || p.MSS == 0 {
		return fmt.Errorf("unsupported profile: use MacOS with a nonzero MSS")
	}
	return nil
}

// Rewrite returns the original slice for unsupported packets and a new slice
// for changes. It never mutates pkt. Malformed packets return an error as well
// as the original bytes, allowing the daemon to accept them unchanged.
func Rewrite(pkt []byte, p Profile) (out []byte, changed bool, err error) {
	out, changed, _, err = rewrite(pkt, p)
	return
}

func rewrite(pkt []byte, p Profile) ([]byte, bool, string, error) {
	pass := func(reason string) ([]byte, bool, string, error) { return pkt, false, reason, nil }
	bad := func(reason string) ([]byte, bool, string, error) {
		return pkt, false, "malformed", fmt.Errorf("malformed packet: %s", reason)
	}
	if err := p.validate(); err != nil {
		return pkt, false, "profile", err
	}
	if len(pkt) == 0 {
		return bad("empty")
	}
	if pkt[0]>>4 != 4 {
		return pass("non_ipv4")
	}
	if len(pkt) < 20 || pkt[0]&15 < 5 {
		return bad("IPv4 header")
	}
	if pkt[9] != 6 {
		return pass("non_tcp")
	}
	if pkt[0]&15 != 5 {
		return pass("ip_options")
	}
	if binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
		return pass("fragment")
	}
	if int(binary.BigEndian.Uint16(pkt[2:4])) != len(pkt) || len(pkt) < 40 {
		return bad("IP length")
	}
	tcp := pkt[20:]
	if tcp[13]&0x12 != 0x02 {
		return pass("non_initial_syn")
	}
	hlen := int(tcp[12]>>4) * 4
	if hlen < 20 || hlen > len(tcp) {
		return bad("TCP header length")
	}
	if hlen != len(tcp) {
		return pass("payload")
	}
	var seen [9]bool
	var ws byte
	var ts [4]byte
	for opts := tcp[20:]; len(opts) > 0; {
		kind := opts[0]
		if kind == 1 {
			opts = opts[1:]
			continue
		}
		var size int
		switch kind {
		case 2:
			size = 4
		case 3:
			size = 3
		case 4:
			size = 2
		case 8:
			size = 10
		default:
			// EOL is intentionally outside the native Linux allowlist too.
			return pass("unsupported_option")
		}
		if len(opts) < size || int(opts[1]) != size {
			return bad("option length")
		}
		if seen[kind] {
			return pass("duplicate_option")
		}
		seen[kind] = true
		if kind == 3 {
			ws = opts[2]
			if ws > 14 {
				return bad("window scale")
			}
		}
		if kind == 8 {
			copy(ts[:], opts[2:6])
		}
		opts = opts[size:]
	}
	if !seen[2] || !seen[3] || !seen[4] || !seen[8] {
		// Do not enable an option that the originating socket did not offer.
		return pass("missing_required_option")
	}
	out := make([]byte, 64)
	copy(out[:40], pkt[:40])
	binary.BigEndian.PutUint16(out[2:4], 64)
	out[4], out[5], out[10], out[11] = 0, 0, 0, 0
	out[32] = 0xb0 | (tcp[12] & 0x0f)
	binary.BigEndian.PutUint16(out[34:36], p.Window)
	out[36], out[37] = 0, 0
	copy(out[40:], []byte{2, 4, byte(p.MSS >> 8), byte(p.MSS), 1, 3, 3, ws, 1, 1, 8, 10})
	copy(out[52:56], ts[:])
	copy(out[60:64], []byte{4, 2, 0, 0})
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:20]))
	var pseudo [12]byte
	copy(pseudo[:8], out[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], 44)
	binary.BigEndian.PutUint16(out[36:38], checksum(pseudo[:], out[20:]))
	return out, !bytes.Equal(out, pkt), "rewritten", nil
}

// checksum computes the Internet checksum over even-length pseudo/header parts.
func checksum(parts ...[]byte) uint16 {
	var sum uint32
	for _, data := range parts {
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data))
			data = data[2:]
		}
		if len(data) == 1 {
			sum += uint32(data[0]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
