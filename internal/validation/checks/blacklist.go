package checks

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/maskrapp/relay/internal/check"
	"github.com/sirupsen/logrus"
)

type BlacklistCheck struct {
	List []string
}

func (c BlacklistCheck) Validate(ctx context.Context, values check.CheckValues) check.CheckResult {
	reversedIp := c.reverseIp(values.Ip)
	queries := make([]lookupResult, 0)
	start := time.Now()
	for _, v := range c.List {
		result, err := c.query(reversedIp, v)
		if err != nil {
			logrus.Infof("received unexpected error(%v) while querying %v", err, v)
			continue
		}
		if result.Exists {
			return check.CheckResult{
				Reject:  true,
				Message: fmt.Sprintf("IP was found on server: %v with reason(s): %v", v, result.Reasons),
			}
		}
		queries = append(queries, result)
	}
	elapsed := time.Since(start)
	logrus.Infof("queried ip %v in %fms: %v", values.Ip, elapsed.Milliseconds(), queries)
	return check.CheckResult{
		Success: true,
		Message: "Valid IP",
	}
}

type lookupResult struct {
	Address string
	Exists  bool
	Reasons []string
}

func (c BlacklistCheck) query(reversedIp, server string) (lookupResult, error) {
	address := fmt.Sprintf("%v.%v", reversedIp, server)
	res, err := net.LookupHost(address)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return lookupResult{
				Address: address,
				Exists:  false,
			}, nil
		}
		return lookupResult{}, err
	}
	result := lookupResult{Address: address}
	for _, v := range res {
		if strings.HasPrefix(v, "127.0.0.") {
			result.Exists = true
		} else {
			logrus.Info("found unexpected record %v in blacklist dns query for address: %v", v, address)
		}
	}
	if result.Exists {
		records, _ := net.LookupTXT(address)
		for _, v := range records {
			result.Reasons = append(result.Reasons, v)
		}
	}
	return result, nil
}

func (c BlacklistCheck) reverseIp(ip net.IP) string {
	octets := strings.Split(ip.String(), ".")
	for i, j := 0, len(octets)-1; i < j; i, j = i+1, j-1 {
		octets[i], octets[j] = octets[j], octets[i]
	}
	return strings.Join(octets, ".")
}
