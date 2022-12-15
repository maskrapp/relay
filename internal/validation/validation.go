package validation

import (
	"context"

	"github.com/maskrapp/relay/internal/check"
	"github.com/maskrapp/relay/internal/validation/checks"
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

var statelessChecks = map[string]check.Check{
	"spf":  checks.SpfCheck{},
	"dkim": checks.DkimCheck{},
}

func NewValidator() *MailValidator {
	return &MailValidator{statelessChecks}
}

func (v *MailValidator) RunChecks(ctx context.Context, values check.CheckValues) CheckResponse {
	var responses = make(map[string]check.CheckResult)
	var state = make(map[string]any)
	var quarantine bool
	for k, v := range v.checks {
		response := v.Validate(ctx, values)

		if response.Reject {
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

	if dmarcResult.Quarantine {
		quarantine = true
	}

	return CheckResponse{
		Reject:     false,
		Quarantine: quarantine,
	}
}


// // Validate validates an incoming email by using SPF, DKIM and DMARC.
// func (v *MailValidator) Validate(headerFrom, envelopeFrom, mailStr string, ip net.IP) (error, bool) {
//
// 	var spfResult spf.Result = spf.None
// 	var dkimResult *dkim.Verification = nil
// 	var dkimErr error = nil
// 	var dmarcResult *dmarc.Record = nil
// 	var dmarcErr error = nil
// 	s := strings.Split(envelopeFrom, "@")
// 	if len(s) != 2 {
// 		return errors.New("invalid envelope from address"), false
// 	}
// 	envelopeFromDomain := s[1]
//
// 	s2 := strings.Split(headerFrom, "@")
// 	if len(s2) != 2 {
// 		return errors.New("invalid from address"), false
// 	}
//
// 	headerFromDomain := s2[1]
//
// 	wg := sync.WaitGroup{}
//
// 	wg.Add(3)
// 	go func() {
// 		spfResult, _ = v.validateSPF(envelopeFromDomain, envelopeFrom, ip)
// 		wg.Done()
// 	}()
// 	go func() {
// 		dkimResult, dkimErr = v.validateDKIM(mailStr)
// 		wg.Done()
// 	}()
// 	go func() {
// 		dmarcResult, dmarcErr = dmarc.Lookup(headerFromDomain)
// 		wg.Done()
// 	}()
// 	wg.Wait()
//
// 	logrus.Info("SPF RESULT", spfResult)
// 	spfPass := spfResult == spf.Pass
// 	dkimPass := dkimErr != nil
//
// 	if !spfPass && !dkimPass {
// 		logrus.Debugf("both SPF and DKIM failed for address: %v(%v)", envelopeFrom, headerFrom)
//
// 		return errors.New("both SPF and DKIM failed"), false
// 	}
// 	// when there's a DMARC error both checks have to pass. maybe quarantine this instead?
// 	if dmarcErr != nil && (!spfPass || !dkimPass) {
// 		logrus.Debugf("dmarc error: %v for address: %v(%v), spf pass: %v dkim pass: %v", dmarcErr, envelopeFrom, headerFrom, spfPass, dkimPass)
// 		return errors.New("DMARC fail (2)"), false
// 	}
//
// 	dkimAligned := v.isAligned(headerFromDomain, dkimResult.Domain, dmarcResult.DKIMAlignment)
// 	spfAligned := v.isAligned(headerFromDomain, envelopeFromDomain, dmarcResult.SPFAlignment)
//
// 	/*
//
// 		If SPF PASSED and ALIGNED with the “From” domain = DMARC PASS, or
// 		If DKIM PASSED and ALIGNED with the “From” domain = DMARC PASS
//
// 		If both SPF and DKIM FAILED = DMARC FAIL
// 	*/
//
// 	if (spfAligned && spfPass) || (dkimAligned && dkimPass) {
// 		logrus.Debugf("DMARC pass for address: %v(%v)", envelopeFrom, headerFrom)
// 		return nil, false
// 	}
//
// 	switch dmarcResult.Policy {
// 	case dmarc.PolicyNone:
// 		// for now, we are quarantining this.
// 		return nil, true
// 	case dmarc.PolicyQuarantine:
// 		return nil, true
// 	case dmarc.PolicyReject:
// 		return errors.New("DMARC reject"), false
// 	}
// 	return nil, false
// }
