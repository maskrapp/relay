package check

import (
	"context"
	"net"
)

type CheckResult struct {
	Message    string
	Success    bool
	Reject     bool
	Quarantine bool
	Data       map[string]any
}

type CheckValues struct {
	HeaderFrom   string
	EnvelopeFrom string
	Helo         string
	MailData     string
	Ip           net.IP
}

type Check interface {
	Validate(context.Context, CheckValues) CheckResult
}
