//go:build linux

package syn

import (
	"bytes"
	"os"
	"testing"
)

func TestVerifyCapturedRules(t *testing.T) {
	b, err := os.ReadFile("testdata/nft-1.0.6.json")
	if err != nil {
		t.Fatal(err)
	}
	c := DefaultConfig()
	c.Mark = 0x6d735901
	if err := verifyRulesJSON(b, c); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"1836275969", "1"}, {"4949", "4950"}, {"bypass", "fanout"}, {"postrouting", "output"}, {"110", "100"}, {"\"drop\": null", "\"accept\": null"}, {"\"syn\", \"ack\"", "\"syn\""}} {
		altered := bytes.ReplaceAll(b, []byte(pair[0]), []byte(pair[1]))
		if err := verifyRulesJSON(altered, c); err == nil {
			t.Fatalf("accepted incorrect %s", pair[0])
		}
	}
}
