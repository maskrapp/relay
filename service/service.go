package service

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/DusanKasan/parsemail"
	"github.com/maskrapp/relay/mailer"
	"github.com/maskrapp/relay/validator"
	"github.com/mhale/smtpd"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Relay struct {
	smtpd  *smtpd.Server
	logger *logrus.Logger
	mailer *mailer.Mailer
	db     *gorm.DB
}

func New(production bool, privateKeyPath, certificatePath, postgresURI, mailerToken string) *Relay {
	relay := &Relay{}
	db, err := gorm.Open(postgres.Open(postgresURI), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	smtpdServer := &smtpd.Server{
		Handler:     relay.handler(),
		TLSRequired: true,
		AuthHandler: func(remoteAddr net.Addr, mechanism string, username, password, shared []byte) (bool, error) {
			return false, errors.New("Unauthorized")
		},
	}

	relay.db = db
	relay.smtpd = smtpdServer
	relay.logger = logrus.New()
	relay.mailer = mailer.New(mailerToken)
	return relay
}

func (m *Relay) Start() {
	fmt.Println("Starting service...")
	err := m.smtpd.ListenAndServe()
	if err != nil {
		m.logger.Error("SMTPD error", err)
	}
}

func (m *Relay) handler() smtpd.Handler {
	return func(origin net.Addr, from string, to []string, data []byte) error {
		parsedMail, err := parsemail.Parse(bytes.NewReader(data))
		if err != nil {
			m.logger.Error("error parsing incoming email:", err)
			return err
		}
		ip, ok := origin.(*net.TCPAddr)
		if !ok {
			return errors.New("couldnt cast origin to tcp")
		}

		if len(parsedMail.From) > 0 && parsedMail.From[0] != nil {
			from = parsedMail.From[0].Address
		}
		domain := strings.Split(from, "@")[1]
		spfResult, err := validator.ValidateSPF(ip.IP, domain, from)
		if err != nil {
			logMessage := fmt.Sprintf("SPF check failed for mail: %v expected pass but got %v", from, spfResult)
			m.logger.Error(logMessage)
			return errors.New("SPF fail")
		}
		recipients := m.getValidRecipients(to)
		if len(recipients) == 0 {
			return errors.New("not a valid recipient")
		}
		err = m.mailer.ForwardMail(parsedMail.From[0].Name, parsedMail.Subject, parsedMail.HTMLBody, parsedMail.TextBody, recipients)
		if err != nil {
			m.logger.Error(err)
			return err
		}
		m.logger.Info("Forwarded mail to", recipients)
		return nil
	}
}

func (m *Relay) getValidRecipients(to []string) []string {
	recipients := make([]string, 0)
	for _, v := range to {
		//TODO: support more domains in the future
		if strings.Split(v, "@")[1] == "relay.maskr.app" {
			result, err := m.getMask(v)
			if err == nil {
				if result.Enabled {
					recipients = append(recipients, result.Email)
				}
			}
		}
	}
	return recipients
}
func (m *Relay) Handle(email *parsemail.Email, to, from string) {}

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
