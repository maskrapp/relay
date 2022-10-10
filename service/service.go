package service

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"relay/mailer"
	"relay/validator"
	"strings"

	"github.com/DusanKasan/parsemail"
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
	cert, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil {
		panic(err)
	}
	relay := &Relay{}
	db, err := gorm.Open(postgres.Open(postgresURI), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	smtpdServer := &smtpd.Server{
		Handler:     relay.handler(),
		TLSRequired: true,
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{cert}},
		AuthHandler: func(remoteAddr net.Addr, mechanism string, username, password, shared []byte) (bool, error) {
			fmt.Println(remoteAddr, mechanism, username, password, shared)
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
		//TODO: run the following code for every valid element in the 'to' array.
		parsedMail, err := parsemail.Parse(bytes.NewReader(data))
		if err != nil {
			m.logger.Error("error parsing incoming email:", err)
			return err
		}
		fmt.Println("to", parsedMail.To)
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
		var recipient = to[0]
		result, err := m.getMask(recipient)
		if err != nil {
			return err
		}
		err = m.mailer.ForwardMail(result.Email, parsedMail.From[0].Name, parsedMail.Subject, parsedMail.HTMLBody, parsedMail.TextBody)
		if err != nil {
			m.logger.Error(err)
			return err
		}
		logMessage := fmt.Sprintf("Forwarded mail from address %v, to %v", parsedMail.To[0].Address, result.Email)
		m.logger.Info(logMessage)
		return nil
	}
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
