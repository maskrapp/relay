package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/DusanKasan/parsemail"
	"github.com/maskrapp/relay/database"
	"github.com/maskrapp/relay/mailer"
	"github.com/maskrapp/relay/validation"
	"github.com/sirupsen/logrus"
	"github.com/thohui/smtpd"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Relay struct {
	smtpd     *smtpd.Server
	mailer    *mailer.Mailer
	db        *gorm.DB
	validator *validation.MailValidator
}

func New(production bool, dbUser, dbPassword, dbHost, dbDatabase, mailerToken, certificate, key string) *Relay {
	relay := &Relay{}
	uri := fmt.Sprintf("postgres://%v:%v@%v/%v", dbUser, dbPassword, dbHost, dbDatabase)
	db, err := gorm.Open(postgres.Open(uri), &gorm.Config{})
	if err != nil {
		logrus.Panic(err)
	}
	logrus.Info("Succesfully connected to DB")
	smtpdServer := &smtpd.Server{
		Handler: relay.handler(),
		Addr:    "0.0.0.0:25",
		AuthHandler: func(remoteAddr net.Addr, mechanism string, username, password, shared []byte) (bool, error) {
			return false, errors.New("Unauthorized")
		},
		HandlerRcpt: func(remoteAddr net.Addr, from, to string) bool {
			return database.IsValidRecipient(db, to)
		},
	}
	if production {
		cert, err := tls.X509KeyPair([]byte(certificate), []byte(key))
		if err != nil {
			logrus.Panic(err)
		}
		smtpdServer.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		smtpdServer.TLSRequired = true
		logrus.Info("Enabled TLS support")
	}
	relay.validator = validation.NewMailValidator()
	relay.db = db
	relay.smtpd = smtpdServer
	relay.mailer = mailer.New(mailerToken)
	return relay
}

func (r *Relay) Start() {
	logrus.Info("Starting service...")
	err := r.smtpd.ListenAndServe()
	if err != nil {
		logrus.Error("SMTPD error", err)
	}
}

func (r *Relay) handler() smtpd.Handler {
	return func(origin net.Addr, envelopeFrom string, to []string, data []byte) error {
		parsedMail, err := parsemail.Parse(bytes.NewReader(data))
		if err != nil {
			logrus.Error("error parsing incoming email:", err)
			return err
		}
		ip, ok := origin.(*net.TCPAddr)
		if !ok {
			return errors.New("couldn't cast origin to TCP")
		}
		logrus.Debug("Incoming mail from:", parsedMail.From, envelopeFrom)
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

		err, quarantine := r.validator.Validate(from, envelopeFrom, string(data), ip.IP)
		if err != nil {
			logrus.Error(err)
			return err
		}
		subject := parsedMail.Subject
		//TODO: in the future, let users decide what they want to do with quarantined incoming mail; reject or allow.
		if quarantine {
			subject = "[SPAM] " + subject
		}
		recipients := database.GetValidRecipients(r.db, to)
		if len(recipients) == 0 {
			logrus.Debug("found no valid recipients for ", to)
			return nil
		}
		forwardAddress := "no-reply@maskr.app"
		if len(to) == 1 {
			forwardAddress = to[0]
		}
		err = r.mailer.ForwardMail(parsedMail.From[0].Name, forwardAddress, subject, parsedMail.HTMLBody, parsedMail.TextBody, recipients)
		if err != nil {
			logrus.Error(err)
			return err
		}
		logrus.Debug("Forwarded mail to ", recipients, " from address ", forwardAddress)
		return nil
	}
}

// TODO: move this to different pkg

func (r *Relay) Shutdown() {
	logrus.Info("Gracefully shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	err := r.smtpd.Shutdown(ctx)
	if err != nil {
		logrus.Error(err)
	}
}
