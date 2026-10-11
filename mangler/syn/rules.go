package syn

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

const TableName = "mirage_syn"

// Rules uses postrouting after source NAT (priority 100). This also works without
// NAT: it sees the final IPv4 addresses and thus checksums the actual wire tuple.
func Rules(c Config) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintln(&b, "table inet mirage_syn {")
	fmt.Fprintln(&b, "  chain outbound {")
	fmt.Fprintln(&b, "    type filter hook postrouting priority 110; policy accept;")
	if c.SYN.Enabled {
		fmt.Fprintf(&b, "    ip protocol tcp tcp flags & (syn | ack) == syn meta mark 0x%x counter queue num %d bypass comment \"mirage-syn IPv4\"\n", c.Mark, c.SYN.QueueNum)
		if c.IPv6 == "block" {
			fmt.Fprintf(&b, "    meta nfproto ipv6 meta l4proto tcp tcp flags & (syn | ack) == syn meta mark 0x%x counter drop comment \"mirage-syn IPv6 fail closed\"\n", c.Mark)
		}
	}
	fmt.Fprintln(&b, "  }")
	fmt.Fprintln(&b, "}")
	return b.String(), nil
}

func nft(ctx context.Context, input string, args ...string) ([]byte, error) {
	path, err := exec.LookPath("nft")
	if err != nil {
		path = "/usr/sbin/nft"
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = strings.NewReader(input)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return b, fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(b)))
	}
	return b, nil
}

// InstallRules refuses to take over an existing table. Run owns exactly the table
// it created; it must never silently delete another daemon's live rules.
func InstallRules(ctx context.Context, c Config) error {
	rules, err := Rules(c)
	if err != nil {
		return err
	}
	// 'create' provides an atomic EEXIST guard; 'add table' would be idempotent.
	_, err = nft(ctx, "create table inet mirage_syn\n"+rules, "-f", "-")
	return err
}

func UninstallRules(ctx context.Context) error {
	_, err := nft(ctx, "", "delete", "table", "inet", TableName)
	if err != nil && strings.Contains(err.Error(), "No such file or directory") {
		return nil
	}
	return err
}
