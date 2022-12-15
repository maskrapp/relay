package checks_test

import (
	"context"
	"net"
	"testing"

	"github.com/maskrapp/relay/internal/check"
	"github.com/maskrapp/relay/internal/validation/checks"
	"github.com/stretchr/testify/assert"
)

func TestReverseDNS(t *testing.T) {
	c := checks.ReverseDnsCheck{}
	values := check.CheckValues{
		Ip:   net.ParseIP("209.85.221.51"),
		Helo: "mail-wr1-f51.google.com",
	}

	result := c.Check(context.Background(), values)
	assert.Equal(t, true, result.Success)
}
