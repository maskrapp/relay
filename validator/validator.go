package validator

import (
	"errors"
	"fmt"
	"net"

	"blitiri.com.ar/go/spf"
)

func ValidateSPF(ip net.IP, domain string, sender string) (spf.Result, error) {
	result, _ := spf.CheckHostWithSender(ip, domain, sender)
	if result == spf.Pass {
		return spf.Pass, nil
	}
	message := fmt.Sprintf("expected PASS, got %v", result)
	return result, errors.New(message)
}
