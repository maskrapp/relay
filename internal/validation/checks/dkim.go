package checks

import (
	"context"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/maskrapp/relay/internal/check"
)

type DkimCheck struct{}

func (c DkimCheck) Validate(ctx context.Context, values check.CheckValues) check.CheckResult {

	verifications, err := dkim.Verify(strings.NewReader(values.MailData))
	if err != nil {
		return check.CheckResult{
			Message: err.Error(),
			Success: false,
			Data: map[string]any{
				"dkim_pass": false,
			},
		}
	}
	if len(verifications) == 0 {
		return check.CheckResult{
			Message: "Domain does not have any DKIM records",
			Success: false,
			Data: map[string]any{
				"dkim_pass": false,
			},
		}
	}
	for _, v := range verifications {
		if v.Err == nil {
			return check.CheckResult{
				Message: "Found valid DKIM record",
				Success: true,
				Data: map[string]any{
					"dkim_pass":   true,
					"dkim_domain": v.Domain,
				},
			}
		}
	}

	return check.CheckResult{
		Message: "DKIM check failed",
		Success: false,
		Data: map[string]any{
			"dkim_pass": false,
		},
	}
}
