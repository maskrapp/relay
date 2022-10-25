package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/DusanKasan/parsemail"
	"github.com/maskrapp/relay/mailer"
	"github.com/maskrapp/relay/smtpd"
	"github.com/maskrapp/relay/validator"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Relay struct {
	smtpd       *smtpd.Server
	logger      *logrus.Logger
	mailer      *mailer.Mailer
	db          *gorm.DB
	healthcheck *http.Server
}

func New(production bool, dbUser, dbPassword, dbHost, dbDatabase, mailerToken, certificate, key string) *Relay {
	relay := &Relay{logger: logrus.New()}
	uri := fmt.Sprintf("postgres://%v:%v@%v/%v", dbUser, dbPassword, dbHost, dbDatabase)
	db, err := gorm.Open(postgres.Open(uri), &gorm.Config{})
	if err != nil {
		relay.logger.Panic(err)
	}
	relay.logger.Info("Succesfully connected to DB")
	smtpdServer := &smtpd.Server{
		Handler: relay.handler(),
		Addr:    "0.0.0.0:25",
		AuthHandler: func(remoteAddr net.Addr, mechanism string, username, password, shared []byte) (bool, error) {
			return false, errors.New("Unauthorized")
		},
	}
	if production {
		cert, err := tls.X509KeyPair([]byte(certificate), []byte(key))
		if err != nil {
			relay.logger.Panic(err)
		}
		smtpdServer.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		smtpdServer.TLSRequired = true
		relay.logger.Info("Enabled TLS support")
	}
	relay.db = db
	relay.smtpd = smtpdServer
	relay.mailer = mailer.New(mailerToken)
	relay.healthcheck = relay.createHealthcheckServer()
	return relay
}

func (r *Relay) createHealthcheckServer() *http.Server {
	srv := &http.Server{Addr: "0.0.0.0:80"}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("healthy"))
	})
	return srv
}

func (r *Relay) Start() {
	r.logger.Info("Starting service...")
	go r.healthcheck.ListenAndServe()
	err := r.smtpd.ListenAndServe()
	if err != nil {
		r.logger.Error("SMTPD error", err)
	}
}

func (r *Relay) handler() smtpd.Handler {
	return func(origin net.Addr, from string, to []string, data []byte) error {
		parsedMail, err := parsemail.Parse(bytes.NewReader(data))
		if err != nil {
			r.logger.Error("error parsing incoming email:", err)
			return err
		}
		ip, ok := origin.(*net.TCPAddr)
		if !ok {
			return errors.New("couldn't cast origin to TCP")
		}

		r.logger.Info("Incoming mail:", parsedMail)

		if len(parsedMail.From) > 0 && parsedMail.From[0] != nil {
			from = parsedMail.From[0].Address
		}
		domain := strings.Split(from, "@")[1]
		spfResult, err := validator.ValidateSPF(ip.IP, domain, from)
		if err != nil {
			logMessage := fmt.Sprintf("SPF check failed for mail: %v expected pass but got %v", from, spfResult)
			r.logger.Error(logMessage)
			return errors.New("SPF fail")
		}
		recipients := r.getValidRecipients(to)
		if len(recipients) == 0 {
			r.logger.Info("found no valid recipients for ", to)
			return nil
		}
		err = r.mailer.ForwardMail(parsedMail.From[0].Name, parsedMail.Subject, parsedMail.HTMLBody, parsedMail.TextBody, recipients)
		if err != nil {
			r.logger.Error(err)
			return err
		}
		r.logger.Info("Forwarded mail to", recipients)
		return nil
	}
}

func (r *Relay) getValidRecipients(to []string) []string {
	recipients := make([]string, 0)
	for _, v := range to {
		//TODO: support more domains in the future
		if strings.Split(v, "@")[1] == "relay.maskr.app" {
			result, err := r.getMask(v)
			if err == nil {
				if result.Enabled {
					recipients = append(recipients, result.Email)
				}
			}
		}
	}
	return recipients
}

func (r *Relay) Shutdown() {
	r.logger.Info("Gracefully shutting down...")
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		err := r.smtpd.Shutdown(context.TODO())
		if err != nil {
			r.logger.Error(err)
		}
		wg.Done()
	}()
	go func() {
		err := r.healthcheck.Shutdown(context.TODO())
		if err != nil {
			r.logger.Error(err)
		}
		wg.Done()
	}()
	wg.Wait()
}

type record struct {
	Mask    string `json:"mask"`
	Email   string `json:"email"`
	Enabled bool   `json:"enabled"`
}

func (r *Relay) getMask(mask string) (*record, error) {
	record := &record{}
	err := r.db.Table("masks").Select("masks.mask, masks.enabled, emails.email").Joins("inner join emails on emails.id = masks.forward_to").Where("masks.mask = ?", mask).First(&record).Error
	return record, err
}
