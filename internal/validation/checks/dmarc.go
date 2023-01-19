package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/emersion/go-msgauth/dmarc"
	"github.com/maskrapp/relay/internal/check"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
)

// DMARC relies on the results of SPF and DKIM, therefore we cannot implement this the same way we implement the other checks.

type DmarcCheck struct{}

func (c DmarcCheck) Name() string {
  return "dmarc"
}

func (c DmarcCheck) Validate(ctx context.Context, values check.CheckValues, state map[string]any) check.CheckResult {
	split := strings.Split(values.HeaderFrom, "@")
	if len(split) != 2 {
		return check.CheckResult{
			Message: fmt.Sprintf("headerFrom split failed: %v", values.HeaderFrom),
			Success: false,
			Reject:  true,
		}
	}

	split2 := strings.Split(values.EnvelopeFrom, "@")
	if len(split2) != 2 {
		return check.CheckResult{
			Message: fmt.Sprintf("envelopeFrom split failed: %v", values.EnvelopeFrom),
			Success: false,
			Reject:  true,
		}
	}

	headerFromDomain := split[1]
	envelopeFromDomain := split2[1]
	result, err := dmarc.Lookup(headerFromDomain)

	val, ok := state["dkim_pass"]
	val2, ok2 := state["spf_pass"]
	if !ok || !ok2 {
		return check.CheckResult{
			Message: "state is missing",
			Reject:  true,
		}
	}
	dkimPass := val.(bool)
	spfPass := val2.(bool)

	if err != nil && (!spfPass || !dkimPass) {
		logrus.Debugf("dmarc error: %v for address: %v(%v), spf pass: %v dkim pass: %v", err, values.EnvelopeFrom, values.HeaderFrom, spfPass, dkimPass)
		return check.CheckResult{
			Message: "SPF or DKIM failed, with DMARC failing too",
			Reject:  true,
		}
	}

	var dkimDomain string
	val, ok = state["dkim_domain"]
	if ok {
		dkimDomain = val.(string)
	}

	dkimAligned := c.isAligned(headerFromDomain, dkimDomain, result.DKIMAlignment)
	spfAligned := c.isAligned(headerFromDomain, envelopeFromDomain, result.SPFAlignment)

	/*

		If SPF PASSED and ALIGNED with the “From” domain = DMARC PASS, or
		If DKIM PASSED and ALIGNED with the “From” domain = DMARC PASS

		If both SPF and DKIM FAILED = DMARC FAIL
	*/

	if (spfAligned && spfPass) || (dkimAligned && dkimPass) {
		logrus.Debugf("DMARC pass for address: %v(%v)", values.EnvelopeFrom, values.HeaderFrom)
		return check.CheckResult{
			Success: true,
			Message: "DMARC pass",
		}
	}

	switch result.Policy {
	case dmarc.PolicyNone:
		// for now, we are quarantining this.
		return check.CheckResult{
			Message:    "DMARC pass",
			Quarantine: true,
		}
	case dmarc.PolicyQuarantine:
		return check.CheckResult{
			Message:    "quarantine",
			Quarantine: true,
		}
	case dmarc.PolicyReject:
		return check.CheckResult{
			Success: false,
			Message: "DMARC reject",
			Reject:  true,
		}
	default:
		return check.CheckResult{
			Success: false,
			Reject:  true,
		}
	}
}

// credit: maddy
func (c *DmarcCheck) isAligned(fromDomain, authDomain string, mode dmarc.AlignmentMode) bool {

	if mode == dmarc.AlignmentStrict {
		return strings.EqualFold(fromDomain, authDomain)
	}

	orgDomainFrom, err := publicsuffix.EffectiveTLDPlusOne(fromDomain)
	if err != nil {
		return false
	}
	authDomainFrom, err := publicsuffix.EffectiveTLDPlusOne(authDomain)
	if err != nil {
		return false
	}

	return strings.EqualFold(orgDomainFrom, authDomainFrom)
}
