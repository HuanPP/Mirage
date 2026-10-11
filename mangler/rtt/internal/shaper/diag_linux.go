//go:build linux

package shaper

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
)

// inet_diag returns established IPv4/IPv6 sockets. No listening socket, payload,
// process access, or packet interception is needed. TCP_INFO.rtt is microseconds.
func ClientRTTs(port uint16) (map[string]float64, error) {
	result := map[string]float64{}
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		fd, e := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_INET_DIAG)
		if e != nil {
			return nil, e
		}
		e = diagFamily(fd, family, port, result)
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
	}
	return result, nil
}
func diagFamily(fd int, family byte, port uint16, result map[string]float64) error {
	if e := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); e != nil {
		return e
	}
	req := make([]byte, 72)
	n := binary.NativeEndian
	n.PutUint32(req, 72)
	n.PutUint16(req[4:], 20)
	n.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	n.PutUint32(req[8:], 1)
	req[16] = family
	req[17] = unix.IPPROTO_TCP
	req[18] = 2
	n.PutUint32(req[20:], 1<<1)
	n.PutUint32(req[64:], 0xffffffff)
	n.PutUint32(req[68:], 0xffffffff)
	if e := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); e != nil {
		return e
	}
	buf := make([]byte, 1<<20)
	for {
		size, _, e := unix.Recvfrom(fd, buf, 0)
		if e != nil {
			return e
		}
		if size == len(buf) {
			return fmt.Errorf("inet_diag truncated")
		}
		for off := 0; off+16 <= size; {
			length := int(n.Uint32(buf[off:]))
			if length < 16 || off+length > size {
				return fmt.Errorf("malformed inet_diag message")
			}
			typ := n.Uint16(buf[off+4:])
			payload := buf[off+16 : off+length]
			if typ == unix.NLMSG_DONE {
				return nil
			}
			if typ == unix.NLMSG_ERROR {
				if len(payload) < 4 {
					return fmt.Errorf("short netlink error")
				}
				code := int32(n.Uint32(payload))
				if code != 0 {
					return unix.Errno(-code)
				}
			}
			if typ == 20 && len(payload) >= 72 && binary.BigEndian.Uint16(payload[4:]) == port {
				for a := 72; a+4 <= len(payload); {
					l := int(n.Uint16(payload[a:]))
					if l < 4 || a+l > len(payload) {
						break
					}
					if n.Uint16(payload[a+2:])&0x3fff == 2 && l >= 4+72 {
						info := payload[a+4 : a+l]
						rtt := n.Uint32(info[68:])
						if rtt > 0 {
							result[fmt.Sprintf("%x", payload[4:40])] = float64(rtt) / 1000
						}
					}
					a += (l + 3) &^ 3
				}
			}
			off += (length + 3) &^ 3
		}
	}
}
