package checks

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/maskrapp/relay/internal/check"
	"github.com/sirupsen/logrus"
)

type ReverseDnsCheck struct{}

func (c ReverseDnsCheck) Validate(ctx context.Context, values check.CheckValues) check.CheckResult {
	resultChan := make(chan check.CheckResult, 1)
	go func() {
		logrus.Info("running rdns check")
		result := c.runCheck(values)
		resultChan <- result
	}()
	select {
	case <-ctx.Done():
		return check.CheckResult{
			Success: false,
			Message: "check was cancelled by context",
		}
	case result := <-resultChan:
		return result
	}
}

func (c ReverseDnsCheck) runCheck(values check.CheckValues) check.CheckResult {
	ptrs, err := net.LookupAddr(values.Ip.String())
	if err != nil {
		return check.CheckResult{
			Success: false,
			Reject:  true,
			Message: fmt.Sprintf("address lookup error: %v", err.Error()),
		}
	}
	ptrRecord := strings.TrimSuffix(ptrs[0], ".")
	if ptrRecord != values.Helo {
		logrus.Debugf("PTR record %v does not match hostname %v", ptrRecord, values.Helo)
		return check.CheckResult{
			Success: false,
			Reject:  false,
			Message: fmt.Sprintf("PTR record(%v) does not match helo(%v)", ptrRecord, values.Helo),
		}
	}
	return check.CheckResult{
		Success: true,
		Message: "PTR record matches hostname",
	}
}
