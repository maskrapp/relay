package validation

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/maskrapp/relay/internal/check"
	"github.com/maskrapp/relay/internal/global"
	"github.com/maskrapp/relay/internal/rbl"
	"github.com/maskrapp/relay/internal/validation/checks"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type MailValidator struct {
	checks []check.Check
}

type CheckResponse struct {
	Reject     bool
	Reason     string
	Quarantine bool
}

func NewValidator(ctx global.Context) *MailValidator {
	var statelessChecks = []check.Check{
		checks.SpfCheck{},
		checks.DkimCheck{},
		checks.ReverseDnsCheck{},
		checks.BlacklistCheck{List: rbl.CreateRBL(ctx)},
	}
	return &MailValidator{statelessChecks}
}

func (v *MailValidator) RunChecks(c context.Context, values check.CheckValues) CheckResponse {
	stateMutex := sync.Mutex{}
	state := make(map[string]interface{})
	quarantine := atomic.Bool{}
	var reject *struct {
		Reason string
	} = nil
	once := sync.Once{}
	eg, ctx := errgroup.WithContext(c)
	start := time.Now()
	for _, v := range v.checks {
		value := v
		logrus.Debugf("running check %v", v.Name())
		eg.Go(func() error {
			now := time.Now()
			defer func() {
				elapsed := time.Since(now)
				logrus.Infof("finished check %v in %vms", value.Name(), elapsed.Milliseconds())
			}()
			result := value.Validate(ctx, values)
			if result.Reject {
				once.Do(func() {
					reject = &struct{ Reason string }{
						Reason: result.Message,
					}
				})
				logrus.Infof("received reject from check %v with response: %v", value.Name(), result)
				return fmt.Errorf("received reject from check %v", value.Name())
			}
			if result.Quarantine {
				quarantine.Store(true)
			}
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
		Quarantine: quarantine.Load() || dmarcResult.Quarantine,
	}
}
