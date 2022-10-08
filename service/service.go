package service

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"relay/logger"
	"relay/validator"
	"strings"

	"github.com/DusanKasan/parsemail"
	"github.com/mhale/smtpd"
)

type Relay struct {
	smtpd  *smtpd.Server
	logger *logger.Logger
}

func New(privateKeyPath, certificatePath, mongoURI string) *Relay {
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
	relay.logger = logger.New(mongoURI)
	return relay
}

func (m *Relay) Start() error {
	return m.smtpd.ListenAndServe()
}

func (m *Relay) handler() smtpd.Handler {
	return func(origin net.Addr, from string, to []string, data []byte) error {
		parsedMail, err := parsemail.Parse(bytes.NewReader(data))
		if err != nil {
			fmt.Println("parse mail err", err)
			return err
		}
		// subject := msg.Header.Get("Subject")
		// log.Printf("Received mail from %s for %s with subject %s", from, to[0], subject)
		ip, ok := origin.(*net.TCPAddr)
		if !ok {
			fmt.Println("tcp err")
			return errors.New("couldnt cast origin to tcp")
		}
		domain := strings.Split(from, "@")[1]
		spfResult, _ := validator.ValidateSPF(ip.IP, domain, from)
		dataMap := map[string]interface{}{
			"spf_result": string(spfResult),
		}
		marshalResult, err := json.Marshal(parsedMail)
		if err != nil {
			fmt.Println("marshal error")
		}
		err = json.Unmarshal(marshalResult, &dataMap)
		if err != nil {
			fmt.Println("unmarshal error")
		}
		m.logger.Log(dataMap)
		return nil
	}
}
