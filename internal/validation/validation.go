package validation

import (
	"context"

	"github.com/maskrapp/relay/internal/check"
	"github.com/maskrapp/relay/internal/global"
	"github.com/maskrapp/relay/internal/rbl"
	"github.com/maskrapp/relay/internal/validation/checks"
	"github.com/sirupsen/logrus"
)

type MailValidator struct {
	// stateless checks
	checks map[string]check.Check
}

type CheckResponse struct {
	Reject     bool
	Reason     string
	Quarantine bool
}

func NewValidator(ctx global.Context) *MailValidator {
	var statelessChecks = map[string]check.Check{
		"spf":         checks.SpfCheck{},
		"dkim":        checks.DkimCheck{},
		"reverse_dns": checks.ReverseDnsCheck{},
		"dnsbl":       checks.BlacklistCheck{List: rbl.CreateRBL(ctx)},
	}
	return &MailValidator{statelessChecks}
}

func (v *MailValidator) RunChecks(c context.Context, values check.CheckValues) CheckResponse {
	var responses = make(map[string]check.CheckResult)
	var state = make(map[string]any)
	var quarantine bool
	ctx, cancel := context.WithCancel(c)
	defer cancel()
	for k, v := range v.checks {
		response := v.Validate(ctx, values)

		if response.Reject {
			logrus.Info("received reject from check %v with response: %v", k, response)
			cancel()
			return CheckResponse{
				Reject: true,
				Reason: response.Message,
			}
		}
		if response.Quarantine {
			quarantine = true
		}
		responses[k] = response
		for k2, v2 := range response.Data {
			state[k2] = v2
		}
	}
	//TODO: implement the stateful checks properly
	dmarcCheck := &checks.DmarcCheck{}
	dmarcResult := dmarcCheck.Validate(ctx, values, state)

	if dmarcResult.Reject {
		return CheckResponse{
			Reject: true,
			Reason: dmarcResult.Message,
		}
	}

	return CheckResponse{
		Reject:     false,
		Quarantine: quarantine || dmarcResult.Quarantine,
	}
}
