package validator

import (
	"errors"
	"fmt"
	"net"

	"blitiri.com.ar/go/spf"
)

func ValidateSPF(ip net.IP, domain string, sender string) error {
	result, _ := spf.CheckHostWithSender(ip, domain, sender)
	if result == spf.Pass {
		return nil
	}
	message := fmt.Sprintf("expected PASS, got %v", result)
	return errors.New(message)
}
