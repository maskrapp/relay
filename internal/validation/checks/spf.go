package checks

import (
	"context"
	"fmt"

	"blitiri.com.ar/go/spf"
	"github.com/maskrapp/relay/internal/check"
)

type SpfCheck struct{}


func (s SpfCheck) Validate(ctx context.Context, values check.CheckValues) check.CheckResult {
	result, _ := spf.CheckHostWithSender(values.Ip, values.Helo, values.EnvelopeFrom)
	if result != spf.Pass {
		return check.CheckResult{
			Message: fmt.Sprintf("expected pass, but got %v", result),
			Success: false,
      Data: map[string]any{
        "spf_pass": false,
      },
		}
	}
	return check.CheckResult{
		Message: "SPF pass",
		Success: true,
    Data: map[string]any{
      "spf_pass": true,
    },
	}
}
