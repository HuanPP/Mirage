//go:build linux

package syn

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"
)

// Run binds before installing rules and removes its rules before closing the
// queue. Queue overflow and absence of a listener both fail open for IPv4.
func Run(ctx context.Context, cfg Config) (result error) {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if !cfg.SYN.Enabled {
		return fmt.Errorf("syn.enabled is false")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	q, err := nfqueue.Open(&nfqueue.Config{
		NfQueue: cfg.SYN.QueueNum, AfFamily: unix.AF_INET,
		MaxPacketLen: 65531, MaxQueueLen: 4096, Copymode: nfqueue.NfQnlCopyPacket,
		Flags:        nfqueue.NfQaCfgFlagFailOpen | nfqueue.NfQaCfgFlagGSO,
		WriteTimeout: time.Second,
	})
	if err != nil {
		return err
	}
	counts := make(map[string]uint64)
	var total, changed, partial uint64
	var scales [15]uint64
	defer func() {
		cancel()
		if err := q.Close(); err != nil && result == nil {
			result = err
		}
		log.Printf("packets=%d rewritten=%d passed=%d partial_checksums=%d reasons=%v wscales=%v", total, changed, total-changed, partial, counts, scales)
	}()
	errors := make(chan error, 1)
	fail := func(err error) int {
		select {
		case errors <- err:
		default:
		}
		cancel()
		return 1
	}
	err = q.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		total++
		if a.PacketID == nil {
			return fail(fmt.Errorf("NFQUEUE message has no packet ID"))
		}
		if a.SkbInfo != nil && len(*a.SkbInfo) >= 4 && binary.BigEndian.Uint32(*a.SkbInfo)&1 != 0 {
			partial++
		}
		var out []byte
		var mod bool
		reason := "missing_payload"
		if a.Mark == nil || *a.Mark != cfg.Mark {
			reason = "unmarked"
		} else if a.Payload != nil && (a.CapLen == nil || int(*a.CapLen) == len(*a.Payload)) {
			out, mod, reason, _ = rewrite(*a.Payload, MacOS(cfg.SYN.MSS))
		} else if a.Payload != nil {
			reason = "truncated"
		}
		counts[reason]++
		if mod {
			changed++
			ws := out[47]
			if scales[ws] == 0 {
				log.Printf("observed_wscale=%d expected_wscale=6 tuning_needed=%t", ws, ws != 6)
			}
			scales[ws]++
			// NFQA_PAYLOAD replacement sets skb->ip_summed = CHECKSUM_NONE in
			// Linux nfqnl_mangle. Never submit a pseudo-header seed here, even
			// when NFQA_SKB_CSUMNOTREADY was present on the original packet.
			err := q.SetVerdictWithOption(*a.PacketID, nfqueue.NfAccept, nfqueue.WithAlteredPacket(out))
			if err != nil {
				return fail(err)
			}
		} else if err := q.SetVerdict(*a.PacketID, nfqueue.NfAccept); err != nil {
			return fail(err)
		}
		return 0
	}, func(err error) int {
		if ctx.Err() != nil {
			return 1
		}
		return fail(err)
	})
	if err != nil {
		return err
	}
	if !cfg.NoRules {
		if err := InstallRules(ctx, cfg); err != nil {
			return err
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := UninstallRules(cleanup); err != nil && result == nil {
				result = err
			}
		}()
	}
	log.Printf("ready queue=%d mark=0x%x profile=macos mss=%d", cfg.SYN.QueueNum, cfg.Mark, cfg.SYN.MSS)
	<-ctx.Done()
	select {
	case err := <-errors:
		return err
	default:
		return nil
	}
}
