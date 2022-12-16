package rbl

import (
	"fmt"

	"github.com/maskrapp/relay/internal/global"
)

func CreateRBL(ctx global.Context) []string {
	return []string{
		"bl.spamcop.net",
		"psbl.surriel.com",
		"ubl.unsubscore.com",
		"b.barracudacentral.org",
		fmt.Sprintf("%v.sbl-xbl.dq.spamhaus.net", ctx.Config().SpamhausToken),
	}
}
