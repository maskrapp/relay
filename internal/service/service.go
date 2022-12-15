package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/DusanKasan/parsemail"
	"github.com/maskrapp/common/models"
	"github.com/maskrapp/relay/internal/check"
	"github.com/maskrapp/relay/internal/database"
	"github.com/maskrapp/relay/internal/global"
	"github.com/maskrapp/relay/internal/validation"
	"github.com/sirupsen/logrus"
	"github.com/thohui/smtpd"
)

type Relay struct {
	smtpd *smtpd.Server
}

func New(ctx global.Context) *Relay {
	domains, err := database.GetAvailableDomains(ctx.Instances().Gorm)
	if err != nil {
		logrus.Error("DB error(GetAvailableDomains): ", err)
	}

	smtpdServer := &smtpd.Server{
		Addr: "0.0.0.0:25",
		HandlerRcpt: func(remoteAddr net.Addr, from, to string) bool {
			return database.IsValidRecipient(ctx.Instances().Gorm, to, domains)
		},
		Handler: handler(ctx, domains),
	}

	if ctx.Config().Production {
		cert, err := tls.X509KeyPair([]byte(ctx.Config().TLS.CertificatePath), []byte(ctx.Config().TLS.PrivateKeyPath))
		if err != nil {
			logrus.Panic(err)
		}
		smtpdServer.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		smtpdServer.TLSRequired = true
		logrus.Info("Enabled TLS")
	}

	logrus.Info("Available domains: ", domains)
	return &Relay{smtpdServer}
}

func (r *Relay) Start() {
	logrus.Info("Starting service...")
	err := r.smtpd.ListenAndServe()
	if err != nil {
		logrus.Error("SMTPD error: ", err)
	}
}

func (r *Relay) Shutdown() {
	logrus.Info("Gracefully shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	err := r.smtpd.Shutdown(ctx)
	if err != nil {
		logrus.Error(err)
	}
}

func handler(ctx global.Context, availableDomains []models.Domain) smtpd.Handler {
	return func(data smtpd.HandlerData) error {
		parsedMail, err := parsemail.Parse(bytes.NewReader(data.Data))
		if err != nil {
			logrus.Error("error parsing incoming email:", err)
			return err
		}
		ip, ok := data.RemoteAddr.(*net.TCPAddr)
		if !ok {
			return errors.New("error casting origin to net.TCPAddr")
		}
		logrus.Debug("Incoming mail from:", parsedMail.From, data.From)

		from := ""
		if len(parsedMail.From) > 0 && parsedMail.From[0] != nil {
			from = parsedMail.From[0].Address
		}

		fromSplit := strings.Split(from, "@")
		if len(fromSplit) != 2 {
			return errors.New("invalid address")
		}

		envelopeSplit := strings.Split(from, "@")

		if len(envelopeSplit) != 2 {
			return errors.New("invalid address")
		}
		validator := validation.NewValidator()
		result := validator.RunChecks(ctx, check.CheckValues{
			EnvelopeFrom: data.From,
			HeaderFrom:   from,
			Helo:         data.Helo,
			MailData:     string(data.Data),
			Ip:           ip.IP,
		})
		if result.Reject {
      logrus.Infof("rejecting incoming mail for reason: %v", result.Reason)
			return errors.New(result.Reason)
		}
		subject := parsedMail.Subject
		//TODO: in the future, let users decide what they want to do with quarantined incoming mail; reject or allow.
		if result.Quarantine {
			subject = "[SPAM] " + subject
		}
		db := ctx.Instances().Gorm
		recipients := database.GetValidRecipients(db, data.To, availableDomains)
		if len(recipients) == 0 {
			logrus.Debug("found no valid recipients for ", data.To)
			return nil
		}
		forwardAddress := "no-reply@maskr.app"
		if len(data.To) == 1 {
			forwardAddress = data.To[0]
		}
		err = ctx.Instances().Mailer.ForwardMail(parsedMail.From[0].Name, forwardAddress, subject, parsedMail.HTMLBody, parsedMail.TextBody, recipients)
		if err != nil {
			logrus.Error(err)
			go func() {
				// TODO: do this in a single query
				for _, v := range recipients {
					innerErr := database.IncrementReceivedCount(db, v.Mask)
					if innerErr != nil {
						logrus.Error("DB error(IncrementReceivedCount): ", innerErr)
					}
				}
			}()
			return err
		}
		go func() {
			for _, v := range recipients {
				// TODO: do this in a single query
				innerErr := database.IncrementForwardedCount(db, v.Mask)
				if innerErr != nil {
					logrus.Error("DB error(IncrementForwardedCount): ", innerErr)
				}
			}
		}()
		logrus.Debugf("Forwarded mail to: %v from address: %v", recipients, forwardAddress)
		return nil
	}
}
