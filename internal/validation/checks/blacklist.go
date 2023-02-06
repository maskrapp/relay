package checks

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maskrapp/relay/internal/check"
	"github.com/sirupsen/logrus"
)

type BlacklistCheck struct {
	List []string
}

func (c BlacklistCheck) Name() string {
	return "blacklist"
}

func (c BlacklistCheck) Validate(ctx context.Context, values check.CheckValues) check.CheckResult {
	resultChan := make(chan check.CheckResult, 1)
	go func() {
		result := c.runCheck(values)
		resultChan <- result
	}()
	select {
	case <-ctx.Done():
		return check.CheckResult{
			Success: false,
			Message: "check was cancelled by context",
		}
	case result := <-resultChan:
		return result
	}
}

func (c BlacklistCheck) runCheck(values check.CheckValues) check.CheckResult {
	reversedIp := c.reverseIp(values.Ip)
	queries := make([]lookupResult, 0)
	mutex := sync.Mutex{}
	wg := sync.WaitGroup{}
	start := time.Now()
	blacklisted := atomic.Bool{}
	wg.Add(len(c.List))
	for _, v := range c.List {
		go func(server string) {
			defer wg.Done()
			result := c.query(reversedIp, server)
			if result.Error != nil {
				logrus.Info("(blcheck) received unexpected error: %v", result.Error)
			}
			if result.Exists {
				blacklisted.Store(true)
			}
			mutex.Lock()
			queries = append(queries, result)
			mutex.Unlock()
		}(v)
	}
	wg.Wait()
	elapsed := time.Since(start)
	logrus.Infof("queried ip %v in %vms: %v", values.Ip, elapsed.Milliseconds(), queries)
	if !blacklisted.Load() {
		return check.CheckResult{
			Success: true,
			Message: "Valid IP",
		}
	}
	reasons := make([]string, 0)
	for _, v := range queries {
		reasons = append(reasons, v.Reasons...)
	}
	return check.CheckResult{
		Reject:  true,
		Message: fmt.Sprintf("IP address is blacklisted for the following reason(s): %v", reasons),
	}
}

type lookupResult struct {
	Address string
	Exists  bool
	Reasons []string
	Error   error
}

func (c BlacklistCheck) query(reversedIp, server string) lookupResult {
	address := fmt.Sprintf("%v.%v", reversedIp, server)
	res, err := net.LookupHost(address)
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return lookupResult{
				Address: address,
			}
		}
		return lookupResult{Address: address, Error: err}
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
	return result
}

func (c BlacklistCheck) reverseIp(ip net.IP) string {
	octets := strings.Split(ip.String(), ".")
	for i, j := 0, len(octets)-1; i < j; i, j = i+1, j-1 {
		octets[i], octets[j] = octets[j], octets[i]
	}
	return strings.Join(octets, ".")
}
