//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct config { __u64 delay, minimum, maximum, floor; __s64 sigma, gain; __u32 rho, enabled; };
struct tuple { __u32 daddr, saddr; __u16 dport, sport; };
#define HISTORY 32
struct ack_state { __u64 edt; __u32 ack, tsecr; __u16 window; __u16 ts; __u32 tsval; };
struct flow {
    __u32 initialized;
    __u32 pad;
    struct config cfg;
    __u64 handshake, barrier, last_ack, last_data;
    __s64 jitter;
    __u32 syn_seq;
    __u32 head;
    __u64 recorded;
    struct ack_state departed;
    struct ack_state history[HISTORY];
};
struct sample { struct tuple key; __u32 kind; __u64 now, edt; __s64 jitter; __u32 ack, seq, cpu, flags, original_ack, tsecr, original_tsecr, gso, priority, skstate; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16); __type(key, __u32); __type(value, struct config); } configs SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536); __type(key, struct tuple); __type(value, struct flow); } flows SEC(".maps");
// Linux 6.1 map_check_btf rejects spin locks in LRU_HASH values. Striped ARRAY
// locks retain LRU expiry while serializing every update of an identical tuple.
struct flow_lock { struct bpf_spin_lock lock; };
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 4096); __type(key, __u32); __type(value, struct flow_lock); } locks SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 4096); __type(key, __u32); __type(value, __s32); } normals SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } samples SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u32); } telemetry SEC(".maps");
// Map-backed zero initialization avoids putting a >512-byte history on the BPF
// stack. Map update copies it; this read-only template is never locked or edited.
const struct flow empty_flow = {};

static __always_inline __u64 delay(struct flow *f, __s32 z) {
    // Arithmetic shifts implement Q16 multiplication. Clang 14's BPF backend
    // cannot lower signed division; rounding error is at most one nanosecond.
    __s64 j = ((f->jitter * f->cfg.rho) >> 16) + ((f->cfg.gain * z) >> 16);
    __s64 cap = f->cfg.sigma * 3;
    if (j > cap) j = cap;
    if (j < -cap) j = -cap;
    f->jitter = j;
    __s64 d = (__s64)f->cfg.delay + j;
    if (d < (__s64)f->cfg.floor) d = f->cfg.floor;
    if (d > (__s64)f->cfg.maximum) d = f->cfg.maximum;
    // A burst shares its first ACK's release time. Reserve one history interval
    // at the negative jitter limit so later members never escape the -3sigma
    // delay envelope. This only clips the small extreme tail of the Gaussian.
    return d;
}

static __always_inline int before(__u32 a, __u32 b) { return (__s32)(a - b) < 0; }
static __always_inline int replace32(struct __sk_buff *skb, __u32 off, __u32 csum, __u32 old, __u32 value) {
    if (old == value) return 0;
    if (bpf_l4_csum_replace(skb, csum, old, value, 4)) return -1;
    return bpf_skb_store_bytes(skb, off, &value, 4, 0);
}

struct scheduling {
    struct tuple key;
    __u32 off, flags, old_ack, old_tsecr, old_window, old_tsval;
    __u64 now, natural, edt;
    __s64 jitter;
    __s64 z;
    // Full-width stack stores also clear any previously spilled pointer when
    // the strict !CAP_PERFMON verifier checks clang's reused stack slots.
    __u64 seq, ack, tsecr, kind, pure, syn, ts, window, tsval;
};
// __dev_queue_xmit runs clsact under rcu_read_lock_bh: no same-CPU softirq
// reentry can overwrite this per-CPU scratch. Map storage also prevents stack
// scalar branch histories from multiplying the !CAP_PERFMON verifier work.
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct scheduling); } scratch SEC(".maps");
// Each stage is verified independently. Linux 6.1 without CAP_PERFMON otherwise
// expands the packet-option, history and scheduling branches past 1M steps.
struct { __uint(type, BPF_MAP_TYPE_PROG_ARRAY); __uint(max_entries, 3); __type(key, __u32); __type(value, __u32); } stages SEC(".maps");

// A separate state-only subprogram lets the verifier merge history-search
// paths before checking packet writes, including without CAP_PERFMON.
static __noinline void refresh_departed(struct flow *f, struct flow_lock *guard, __u64 now) {
    bpf_spin_lock(&guard->lock);
    __u32 oldest = (f->head + 1) & (HISTORY - 1);
    __u32 low = 0, high = HISTORY;
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        if (low < high) {
            __u32 mid = (low + high) / 2;
            __u64 stamp = f->history[(oldest + mid) & (HISTORY - 1)].edt;
            if (stamp <= now) low = mid + 1;
            else high = mid;
        }
    }
    if (low) {
        struct ack_state slot = f->history[(oldest + low - 1) & (HISTORY - 1)];
        if (slot.edt > f->departed.edt) f->departed = slot;
    }
    bpf_spin_unlock(&guard->lock);
}

static __noinline int schedule(struct flow *f, struct flow_lock *guard,
                              struct config *snapshot, struct scheduling *p) {
    __u64 now = p->now, natural = p->natural, edt = natural;
    __u32 seq = p->seq, ack = p->ack, tsecr = p->tsecr, tsval = p->tsval, kind = 0;
    __u16 window = p->window;
    __s32 z = p->z;
    __s64 jitter;
    int syn = p->syn;
    int ts = p->ts;
    // clsact runs before the qdisc enqueue lock. Socket locking serializes
    // normal TCP output, but marked forwarding/raw traffic need not share that
    // lock; also CPUs change between process, receive and delack paths. Protect
    // the complete snapshot, AR(1), history and strict EDT update as one unit.
    // All helpers (including map lookups and time/random) are outside this lock.
    bpf_spin_lock(&guard->lock);
    if (!f->initialized || (syn && f->syn_seq != seq)) {
        f->cfg = *snapshot;
        f->initialized = 1;
        f->syn_seq = seq;
        f->handshake = f->barrier = f->last_ack = f->last_data = f->recorded = 0;
        f->jitter = (snapshot->sigma * z) >> 16;
        f->head = 0;
        f->departed = (struct ack_state){};
        #pragma unroll
        for (int i = 0; i < HISTORY; i++) f->history[i] = (struct ack_state){};
        // A missed SYN (e.g. LRU eviction) cannot bypass outstanding delayed
        // ACKs. Hold the replacement flow for the maximum configured delay.
        if (!syn) f->barrier = now + snapshot->maximum;
    }
    if (syn) { bpf_spin_unlock(&guard->lock); return 0; }
    if (!f->handshake) f->handshake = now;
    int pure = p->pure;
    if (pure && f->last_ack) {
        edt = now + delay(f, z);
        if (edt < natural) edt = natural;
        kind = 2;
    } else if (natural < f->handshake + f->cfg.delay) {
        if (!f->barrier) f->barrier = f->handshake + delay(f, z);
        if (edt < f->barrier) edt = f->barrier;
        kind = 1;
    } else if (pure) {
        edt = now + delay(f, z);
        if (edt < natural) edt = natural;
        kind = 2;
    } else {
        if (edt < f->barrier) edt = f->barrier;
    }
    // Bounded, EDT-ordered history. ACK bursts share one release time, with
    // strictly increasing nanosecond offsets. Preserve the kernel's cumulative
    // ACK, rather than repeating a stale ACK and withholding a burst's tail for
    // another RTT. The latest slot is updated until the next recording interval.
    __u64 span = f->cfg.delay + 3 * f->cfg.sigma;
    if (span > f->cfg.maximum) span = f->cfg.maximum;
    __u64 interval = span / (HISTORY - 2);
    struct ack_state latest = f->history[f->head & (HISTORY - 1)];
    if (pure) {
        if (latest.edt && before(ack, latest.ack)) {
            bpf_spin_unlock(&guard->lock);
            return 1;
        }
        if (f->last_ack && latest.edt > now && now - f->recorded < interval) {
            edt = f->last_ack + 1;
        } else {
            if (latest.edt) f->head = (f->head + 1) & (HISTORY - 1);
            f->recorded = now;
        }
        if (edt <= f->last_ack) edt = f->last_ack + 1;
        if (edt <= f->last_data) edt = f->last_data + 1;
        f->last_ack = edt;
        if (ts && latest.ts && before(tsecr, latest.tsecr)) tsecr = latest.tsecr;
        f->history[f->head & (HISTORY - 1)] = (struct ack_state){ .edt = edt, .ack = ack, .tsecr = tsecr, .window = window, .ts = ts, .tsval = tsval };
    } else {
        if (edt <= f->last_data) edt = f->last_data + 1;
        f->last_data = edt;
        struct ack_state departed = f->departed;
        if (!departed.edt && latest.edt) {
            // Handshake data uses the initial ACK information and stays behind
            // that ACK. It must not leak an acknowledgement of early peer data.
            departed = latest;
            if (edt <= f->last_ack) edt = f->last_ack + 1;
        }
        if (departed.edt) {
            f->departed = departed;
            if (before(departed.ack, ack)) ack = departed.ack;
            if (ts && departed.ts && before(departed.tsecr, tsecr)) tsecr = departed.tsecr;
            // Undelayed data must not advance the peer's PAWS timestamp past
            // a queued ACK's original TSval, or that ACK is discarded later.
            if (ts && departed.ts && before(departed.tsval, tsval)) tsval = departed.tsval;
            window = departed.window;
        }
    }
    jitter = f->jitter;
    bpf_spin_unlock(&guard->lock);
    p->ack = ack; p->tsecr = tsecr; p->window = window; p->tsval = tsval;
    p->edt = edt; p->kind = kind; p->jitter = jitter;
    return 0;
}

SEC("tc") int mirage_rtt(struct __sk_buff *skb) {
    __u32 mark = skb->mark;
    struct config *cfg = bpf_map_lookup_elem(&configs, &mark);
    if (!cfg || !cfg->enabled || skb->protocol != bpf_htons(0x0800)) return TC_ACT_OK;
    // Use load_bytes: GSO/nonlinear skbs need not have their entire payload linear.
    __u8 ip[20], tcp[20];
    if (bpf_skb_load_bytes(skb, 14, ip, 20)) return TC_ACT_OK;
    if ((ip[0] >> 4) != 4 || ip[9] != 6 || (ip[6] & 0x3f) || ip[7]) return TC_ACT_OK;
    __u32 ihl = (ip[0] & 15) * 4;
    if (ihl < 20 || bpf_skb_load_bytes(skb, 14 + ihl, tcp, 20)) return TC_ACT_OK;
    __u32 thl = (tcp[12] >> 4) * 4, total = ((__u32)ip[2] << 8) | ip[3];
    if (thl < 20 || total < ihl + thl) return TC_ACT_OK;
    struct tuple key = {};
    __builtin_memcpy(&key.saddr, ip + 12, 4);
    __builtin_memcpy(&key.daddr, ip + 16, 4);
    __builtin_memcpy(&key.sport, tcp, 2);
    __builtin_memcpy(&key.dport, tcp + 2, 2);
    __u8 flags = tcp[13];
    if (flags & 0x04) {
        bpf_map_delete_elem(&flows, &key);
        return TC_ACT_OK;
    }
    int syn = (flags & 0x12) == 0x02;
    if (!syn && (flags & 0x02 || !(flags & 0x10))) return TC_ACT_OK;
    struct flow *f = bpf_map_lookup_elem(&flows, &key);
    if (!f) {
        bpf_map_update_elem(&flows, &key, &empty_flow, BPF_NOEXIST);
    }
    // A single lookup instruction supplies the pointer on every verifier path.
    // This also avoids unprivileged pointer-ID joins without CAP_PERFMON.
    f = bpf_map_lookup_elem(&flows, &key);
    if (!f) return TC_ACT_SHOT;
    __u32 seq, ack, old_ack, tsecr = 0, old_tsecr = 0, old_tsval = 0;
    __u16 window, old_window;
    __builtin_memcpy(&seq, tcp + 4, 4);
    __builtin_memcpy(&old_ack, tcp + 8, 4);
    __builtin_memcpy(&old_window, tcp + 14, 2);
    ack = bpf_ntohl(old_ack);
    window = old_window;
    __u8 options[12];
    int ts = thl >= 32 && !bpf_skb_load_bytes(skb, 14 + ihl + 20, options, 12) &&
             options[0] == 1 && options[1] == 1 && options[2] == 8 && options[3] == 10;
    if (ts) { __builtin_memcpy(&old_tsecr, options + 8, 4); tsecr = bpf_ntohl(old_tsecr); __builtin_memcpy(&old_tsval, options + 4, 4); }
    __u32 index = bpf_get_prandom_u32() & 4095;
    __s32 *normal = bpf_map_lookup_elem(&normals, &index), z = normal ? *normal : 0;
    __u32 lock_index = (key.saddr ^ key.daddr ^ ((__u32)key.sport << 16) ^ key.dport) & 4095;
    struct flow_lock *guard = bpf_map_lookup_elem(&locks, &lock_index);
    if (!guard) return TC_ACT_SHOT;
    __u64 now = bpf_ktime_get_ns(), natural = skb->tstamp;
    if (natural < now) natural = now;
    __u32 scratch_key = 0;
    struct scheduling *p = bpf_map_lookup_elem(&scratch, &scratch_key);
    if (!p) return TC_ACT_SHOT;
    p->key = key; p->off = 14 + ihl; p->flags = flags;
    p->old_ack = old_ack; p->old_tsecr = old_tsecr; p->old_window = old_window;
    p->old_tsval = old_tsval; p->tsval = bpf_ntohl(old_tsval);
    p->now = now; p->natural = natural; p->edt = natural;
    p->z = z; p->seq = seq; p->ack = ack; p->tsecr = tsecr;
    p->window = window; p->syn = syn; p->ts = ts;
    p->pure = !(flags & 7) && total == ihl + thl;
    bpf_tail_call(skb, &stages, 0);
    return TC_ACT_SHOT;
}

SEC("tc") int rtt_release(struct __sk_buff *skb) {
    __u32 zero = 0;
    struct scheduling *p = bpf_map_lookup_elem(&scratch, &zero);
    if (!p) return TC_ACT_SHOT;
    struct flow *f = bpf_map_lookup_elem(&flows, &p->key);
    if (!f) return TC_ACT_SHOT;
    __u32 index = (p->key.saddr ^ p->key.daddr ^ ((__u32)p->key.sport << 16) ^ p->key.dport) & 4095;
    struct flow_lock *guard = bpf_map_lookup_elem(&locks, &index);
    if (!guard) return TC_ACT_SHOT;
    if (!p->syn) refresh_departed(f, guard, p->natural);
    bpf_tail_call(skb, &stages, 1);
    return TC_ACT_SHOT;
}

SEC("tc") int rtt_schedule(struct __sk_buff *skb) {
    __u32 zero = 0, mark = skb->mark;
    struct scheduling *p = bpf_map_lookup_elem(&scratch, &zero);
    struct config *cfg = bpf_map_lookup_elem(&configs, &mark);
    if (!p || !cfg) return TC_ACT_SHOT;
    struct flow *f = bpf_map_lookup_elem(&flows, &p->key);
    if (!f) return TC_ACT_SHOT;
    __u32 index = (p->key.saddr ^ p->key.daddr ^ ((__u32)p->key.sport << 16) ^ p->key.dport) & 4095;
    struct flow_lock *guard = bpf_map_lookup_elem(&locks, &index);
    if (!guard) return TC_ACT_SHOT;
    if (schedule(f, guard, cfg, p)) return TC_ACT_SHOT;
    if (p->syn) return TC_ACT_OK;
    bpf_tail_call(skb, &stages, 2);
    return TC_ACT_SHOT;
}

SEC("tc") int rtt_emit(struct __sk_buff *skb) {
    __u32 zero = 0;
    struct scheduling *p = bpf_map_lookup_elem(&scratch, &zero);
    if (!p) return TC_ACT_SHOT;
    __u64 edt = p->edt;
    __u32 kind = p->kind, ack = p->ack, tsecr = p->tsecr;
    __u32 old_ack = p->old_ack, old_tsecr = p->old_tsecr;
    __u16 window = p->window, old_window = p->old_window;
    __u32 off = p->off, csum = off + 16;
    int ts = p->ts;
    // Linux 6.1 fq's 10s horizon exceeds our 600ms maximum by a wide margin.
    // Checksums are incremental: for CHECKSUM_PARTIAL the TCP checksum stores
    // only the pseudo-header seed, so l4_csum_replace deliberately leaves it
    // unchanged; software/hardware GSO checksums every rewritten segment later.
    // Even undelayed data needs an explicit current EDT: a stale kernel pacing
    // stamp can sort it before an ACK whose EDT has already elapsed in fq.
    skb->tstamp = edt;
    if (replace32(skb, off + 8, csum, old_ack, bpf_htonl(ack))) return TC_ACT_SHOT;
    if (ts && replace32(skb, off + 28, csum, old_tsecr, bpf_htonl(tsecr))) return TC_ACT_SHOT;
    if (ts && replace32(skb, off + 24, csum, p->old_tsval, bpf_htonl(p->tsval))) return TC_ACT_SHOT;
    if (window != old_window) {
        if (bpf_l4_csum_replace(skb, csum, old_window, window, 2) ||
            bpf_skb_store_bytes(skb, off + 14, &window, 2, 0)) return TC_ACT_SHOT;
    }
    // SACK blocks are deliberately preserved. They can expose fresher selective
    // reception and trigger loss recovery; this v1 only delays cumulative ACKs
    // and the usual Linux NOP NOP TS option (nonstandard layouts are untouched).
    __u32 *enabled = bpf_map_lookup_elem(&telemetry, &zero);
    if (enabled && *enabled) {
        struct sample *s = bpf_ringbuf_reserve(&samples, sizeof(*s), 0);
        if (s) {
            s->key = p->key; s->kind = kind; s->now = p->now; s->edt = edt; s->jitter = p->jitter;
            s->ack = bpf_htonl(ack); s->seq = p->seq; s->cpu = bpf_get_smp_processor_id(); s->flags = p->flags;
            s->original_ack = old_ack; s->tsecr = bpf_htonl(tsecr); s->original_tsecr = old_tsecr; s->gso = skb->gso_segs;
            s->priority = skb->priority;
            struct bpf_sock *sk = skb->sk;
            s->skstate = sk ? sk->state : 255;
            bpf_ringbuf_submit(s, 0);
        }
    }
    return TC_ACT_OK;
}
char _license[] SEC("license") = "GPL";
