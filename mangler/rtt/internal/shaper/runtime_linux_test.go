//go:build linux

package shaper

import "testing"

func TestEveryQueueUsesFQ(t *testing.T) {
	good := "qdisc mq 0: root\nqdisc fq 1: parent :1 flow_limit 4096p horizon 10s horizon_drop\nqdisc fq 2: parent :2 flow_limit 4096p horizon 10s horizon_drop\nqdisc clsact ffff: parent ffff:fff1\n"
	if e := validateFQ(good, 600); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"qdisc mq 0: root\nqdisc fq 1: parent :1 flow_limit 4096p horizon 10s\nqdisc fq_codel 2: parent :2", "qdisc fq 1: root flow_limit 4096p horizon 500ms"} {
		if e := validateFQ(bad, 600); e == nil {
			t.Fatal("unsafe EDT layout accepted", bad)
		}
	}
}
