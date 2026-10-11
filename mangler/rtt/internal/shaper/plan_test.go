package shaper

import (
	"strings"
	"testing"
)

func TestMQPlan(t *testing.T) {
	before := "qdisc mq 0: root\nqdisc fq_codel 0: parent :1 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64\n"
	if _, e := MakePlan("ens4", before, false); e == nil {
		t.Fatal("mq changed without authorization")
	}
	p, e := MakePlan("ens4", before, true)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Rollback) != 1 || !strings.Contains(p.Script(), "'parent' ':1' 'fq_codel'") {
		t.Fatal(p)
	}
	if !p.Anonymous {
		t.Fatal("anonymous mq leaf restoration limitation not detected")
	}
	if strings.Contains(ShellCommand(p.Commands[0]), "'root'") {
		t.Fatal("mq root replaced")
	}
}
func TestRejectUnsupported(t *testing.T) {
	if _, e := MakePlan("ens4", "qdisc htb 1: root", true); e == nil {
		t.Fatal("inexact rollback accepted")
	}
}

func TestExactCodelRollback(t *testing.T) {
	p, e := MakePlan("veth0", "qdisc fq_codel 8001: root refcnt 2 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64", true)
	if e != nil {
		t.Fatal(e)
	}
	e = p.ExactRollback(`[{"kind":"fq_codel","root":true,"options":{"limit":10240,"flows":1024,"quantum":1514,"target":4999,"interval":99999,"memory_limit":33554432,"ecn":true,"drop_batch":64}}]`)
	if e != nil {
		t.Fatal(e)
	}
	script := p.Script()
	if !strings.Contains(script, "'target' '5000us'") || !strings.Contains(script, "'interval' '100000us'") {
		t.Fatal(script)
	}
}

func TestKernelDefaultMQ(t *testing.T) {
	before := "qdisc mq 0: root\nqdisc fq_codel 0: parent :1 limit 10240p flows 1024 quantum 1514 target 5ms interval 100ms memory_limit 32Mb ecn drop_batch 64\n"
	raw := `[{"kind":"mq","handle":"0:","root":true,"options":{}},{"kind":"fq_codel","handle":"0:","parent":":1","options":{"limit":10240,"flows":1024,"quantum":1514,"target":4999,"interval":99999,"memory_limit":33554432,"ecn":true,"drop_batch":64}}]`
	for _, custom := range []bool{false, true} {
		p, err := MakePlan("ens4", before, true)
		if err != nil {
			t.Fatal(err)
		}
		candidate := raw
		if custom {
			candidate = strings.Replace(raw, "4999", "6999", 1)
		}
		if err = p.DefaultRollback("ens4", candidate, "fq_codel", 1500); err != nil {
			t.Fatal(err)
		}
		if custom {
			if !p.Anonymous {
				t.Fatal("custom anonymous default accepted")
			}
		} else if p.Anonymous || !strings.Contains(p.Script(), "'del' 'dev' 'ens4' 'root'") {
			t.Fatal(p)
		}
	}
	p, _ := MakePlan("ens4", before, true)
	if err := p.DefaultRollback("ens4", raw, "fq_codel", 1460); err != nil || !p.Anonymous {
		t.Fatal("old-MTU quantum accepted as exact root-delete rollback", err)
	}
}
