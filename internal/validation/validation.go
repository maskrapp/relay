package validation

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/maskrapp/relay/internal/check"
	"github.com/maskrapp/relay/internal/global"
	"github.com/maskrapp/relay/internal/rbl"
	"github.com/maskrapp/relay/internal/syncmap"
	"github.com/maskrapp/relay/internal/validation/checks"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
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
	results := syncmap.Map[string, check.CheckResult]{}
	stateMutex := sync.Mutex{}
	state := make(map[string]interface{})
	quarantine := false
	var reject *struct {
		Reason string
	} = nil
	once := sync.Once{}
	eg, ctx := errgroup.WithContext(c)
	start := time.Now()
	for k, v := range v.checks {
		key, value := k, v
		logrus.Debugf("Running check %v", key)
		eg.Go(func() error {
			now := time.Now()
			defer func() {
				elapsed := time.Since(now)
				logrus.Info("Finished check %v in %vms", key, elapsed.Milliseconds())
			}()
			result := value.Validate(ctx, values)
			if result.Reject {
				once.Do(func() {
					reject = &struct{ Reason string }{
						Reason: result.Message,
					}
				})
				logrus.Infof("received reject from check %v with response: %v", key, result)
				return errors.New("received reject")
			}
			if result.Quarantine {
				quarantine = true
			}
			results.Store(key, result)
			stateMutex.Lock()
			for k2, v2 := range result.Data {
				state[k2] = v2
			}
			stateMutex.Unlock()
			return nil
		})
	}
	eg.Wait()
	if reject != nil {
		return CheckResponse{
			Reject: true,
			Reason: reject.Reason,
		}
	}
	//TODO: implement the stateful checks properly
	dmarcCheck := &checks.DmarcCheck{}
	dmarcResult := dmarcCheck.Validate(ctx, values, state)
	elapsed := time.Since(start)
	logrus.Debugf("Finished all checks in %vms", elapsed.Milliseconds())
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
