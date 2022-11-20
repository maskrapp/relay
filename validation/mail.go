package validation

import (
	"errors"
	"net"
	"strings"
	"sync"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/publicsuffix"
)

type MailValidator struct {
	logger *logrus.Logger
}

func NewMailValidator(logger *logrus.Logger) *MailValidator {
	return &MailValidator{logger: logger}
}

// https://knowledge.ondmarc.redsift.com/en/articles/1739840-all-you-need-to-know-about-spf-dkim-and-dmarc

// Validate validates an incoming email by using SPF, DKIM and DMARC.
func (v *MailValidator) Validate(headerFrom, envelopeFrom, mailStr string, ip net.IP) (error, bool) {

	var spfResult spf.Result = spf.None
	var dkimResult *dkim.Verification = nil
	var dkimErr error = nil
	var dmarcResult *dmarc.Record = nil
	var dmarcErr error = nil
	s := strings.Split(envelopeFrom, "@")
	if len(s) != 2 {
		return errors.New("invalid envelope from address"), false
	}
	envelopeFromDomain := s[1]

	s2 := strings.Split(headerFrom, "@")
	if len(s2) != 2 {
		return errors.New("invalid from address"), false
	}

	headerFromDomain := s2[1]

	wg := sync.WaitGroup{}

	wg.Add(3)
	go func() {
		spfResult, _ = v.validateSPF(envelopeFromDomain, envelopeFrom, ip)
		wg.Done()
	}()
	go func() {
		dkimResult, dkimErr = v.validateDKIM(mailStr)
		wg.Done()
	}()
	go func() {
		dmarcResult, dmarcErr = dmarc.Lookup(headerFromDomain)
		wg.Done()
	}()
	wg.Wait()

	spfPass := spfResult == spf.Pass
	dkimPass := dkimErr != nil

	if !spfPass && !dkimPass {
		v.logger.Debugf("both SPF and DKIM failed for address: %v(%v)", envelopeFrom, headerFrom)

		return errors.New("both SPF and DKIM failed"), false
	}
	// when there's a DMARC error both checks have to pass. maybe quarantine this instead?
	if dmarcErr != nil && (!spfPass || !dkimPass) {
		v.logger.Debugf("dmarc error: %v for address: %v(%v), spf pass: %v dkim pass: %v", envelopeFrom, headerFrom, spfPass, dkimPass)
		return errors.New("DMARC fail (2)"), false
	}

	dkimAligned := v.isAligned(headerFromDomain, dkimResult.Domain, dmarcResult.DKIMAlignment)
	spfAligned := v.isAligned(headerFromDomain, envelopeFromDomain, dmarcResult.SPFAlignment)

	/*

		If SPF PASSED and ALIGNED with the “From” domain = DMARC PASS, or
		If DKIM PASSED and ALIGNED with the “From” domain = DMARC PASS

		If both SPF and DKIM FAILED = DMARC FAIL
	*/

	if (spfAligned && spfPass) || (dkimAligned && dkimPass) {
		v.logger.Debugf("DMARC pass for address: %v(%v)", envelopeFrom, headerFrom)
		return nil, false
	}

	switch dmarcResult.Policy {
	case dmarc.PolicyNone:
		// for now, we are quarantining this.
		return nil, true
	case dmarc.PolicyQuarantine:
		return nil, true
	case dmarc.PolicyReject:
		return errors.New("DMARC reject"), false
	}
	return nil, false
}

var errNoDKIMRecord = errors.New("domain does not have any DKIM DNS records")
var errInvalidRecord = errors.New("DKIM check failed")

func (v *MailValidator) validateDKIM(mailStr string) (*dkim.Verification, error) {
	verifications, err := dkim.Verify(strings.NewReader(mailStr))
	if err != nil {
		return nil, err
	}
	if len(verifications) == 0 {
		return nil, errNoDKIMRecord
	}
	for _, v := range verifications {
		if v.Err == nil {
			logrus.Debug("dkim check succeeded for: ", v)
			return v, nil
		}
	}
	return nil, errInvalidRecord
}

func (v *MailValidator) validateSPF(domain, mailFrom string, ip net.IP) (spf.Result, error) {
	return spf.CheckHostWithSender(ip, domain, mailFrom)
}

// credit: maddy
func (v *MailValidator) isAligned(fromDomain, authDomain string, mode dmarc.AlignmentMode) bool {

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
