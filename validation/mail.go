package validation

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/sirupsen/logrus"
)

type MailValidator struct {
	logger *logrus.Logger
}

func NewMailValidator(logger *logrus.Logger) *MailValidator {
	return &MailValidator{logger: logger}
}

// TODO: perhaps implement DMARC?
func (v *MailValidator) Validate(domain, sender, mailStr string, ip net.IP) error {
	var spfResult spf.Result = spf.None
	var dkimResult *dkim.Verification = nil
	var dkimErr error = nil

	wg := sync.WaitGroup{}

	wg.Add(2)
	go func() {
		spfResult, _ = v.validateSPF(domain, sender, ip)
		wg.Done()
	}()
	go func() {
		dkimResult, dkimErr = v.validateDKIM(mailStr)
		wg.Done()
	}()
	wg.Wait()

	// for now, only one of the two checks has to pass in order for the entire thing to succeed. TODO: look into making this better.
	if spfResult == spf.Pass || dkimErr == nil {
		return nil
	}

	message := fmt.Sprintf("mail from %v did not meet spf and dkim requirements. spf: %v dkim: %v dkim err %v", sender, spfResult, dkimResult, dkimErr)
	return errors.New(message)
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
			logrus.Info("dkim check succeeded for: ", v)
			return v, nil
		}
	}
	return nil, errInvalidRecord
}

func (v *MailValidator) validateSPF(domain, sender string, ip net.IP) (spf.Result, error) {
	return spf.CheckHostWithSender(ip, domain, sender)
}
