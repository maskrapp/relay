package checks

import (
	"context"
	"errors"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/maskrapp/relay/internal/check"
)

var errNoDKIMRecord = errors.New("domain does not have any DKIM records")
var errInvalidRecord = errors.New("DKIM check failed")

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
			Message: errNoDKIMRecord.Error(),
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
		Message: errInvalidRecord.Error(),
		Success: false,
		Data: map[string]any{
			"dkim_pass": false,
		},
	}
}
