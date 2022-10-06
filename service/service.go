package service

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/mail"
	"relay/validator"
	"strings"

	"github.com/mhale/smtpd"
)

type Relay struct {
	smtpd *smtpd.Server
}

func New(privateKeyPath, certificatePath string) *Relay {
	cert, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil {
		panic(err)
	}
	relay := &Relay{}
	smtpdServer := &smtpd.Server{
		Handler:     relay.handler(),
		TLSRequired: true,
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{cert}},
		AuthHandler: func(remoteAddr net.Addr, mechanism string, username, password, shared []byte) (bool, error) {
			fmt.Println(remoteAddr, mechanism, username, password, shared)
			return false, errors.New("Unauthorized")
		},
	}
	relay.smtpd = smtpdServer
	return relay
}

func (m *Relay) Start() error {
	return m.smtpd.ListenAndServe()
}

func (m *Relay) handler() smtpd.Handler {
	return func(origin net.Addr, from string, to []string, data []byte) error {
		msg, err := mail.ReadMessage(bytes.NewReader(data))
		if err != nil {
			panic(err)
		}
		subject := msg.Header.Get("Subject")
		log.Printf("Received mail from %s for %s with subject %s", from, to[0], subject)
		fmt.Println("data", string(data))
		ip, ok := origin.(*net.TCPAddr)
		if !ok {
			return errors.New("couldnt cast origin to tcp")
		}
		domain := strings.Split(from, "@")[1]
		err = validator.ValidateSPF(ip.IP, domain, from)
		if err != nil {
			fmt.Println(err)
			return err
		}
		return nil
	}
}
