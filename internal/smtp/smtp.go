package smtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/mail"
	"strings"

	"github.com/DusanKasan/parsemail"
	"github.com/maskrapp/relay/internal/check"
	"github.com/maskrapp/relay/internal/global"
	"github.com/maskrapp/relay/internal/mailer"
	main_api "github.com/maskrapp/relay/internal/pb/main_api/v1"
	"github.com/maskrapp/relay/internal/validation"
	"github.com/maskrapp/smtpd"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func New(ctx global.Context) *smtpd.Server {
	validator := validation.NewValidator(ctx)
	mailer := mailer.New(ctx.Config().ZeptoMail.EmailToken)

	smtpdServer := &smtpd.Server{
		Addr:     "0.0.0.0:25",
		Hostname: ctx.Config().Hostname,
		Debug:    ctx.Config().Logger.LogLevel == "debug",
		LogWrite: func(remoteIP, verb, line string) {
			if !strings.Contains(line, "smtpd ESMTP Service ready") {
				logrus.Infof("[WRITE] %v %v %v", remoteIP, verb, line)
			}
		},
		LogRead: func(remoteIP, verb, line string) {
			logrus.Infof("[READ] %v %v %v", remoteIP, verb, line)
		},
		HandlerRcpt: createHanderRcpt(ctx.Instances().GrpcClient),
		Handler:     createHandler(ctx.Instances().GrpcClient, validator, mailer),
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

	return smtpdServer
}

func createHanderRcpt(backendClient main_api.MainAPIServiceClient) smtpd.HandlerRcpt {
	return func(remoteAddr net.Addr, from, to string) bool {
		_, err := mail.ParseAddress(from)
		if err != nil {
			return false
		}
		_, err = backendClient.CheckMask(context.TODO(), &main_api.CheckMaskRequest{MaskAddress: to})
		if err != nil {
			status := status.Convert(err)
			if status.Code() != codes.NotFound {
				logrus.Errorf("backend client err: %v", status.Err())
			}
			return false
		}
		return true
	}
}

func createHandler(apiClient main_api.MainAPIServiceClient, validator *validation.MailValidator, mailer *mailer.Mailer) smtpd.Handler {
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

		var from string
		if len(parsedMail.From) > 0 && parsedMail.From[0] != nil {
			from = parsedMail.From[0].Address
		}

		ctx := context.TODO() //TODO: change the context once this is implemented in the smtpd package.
		values := check.CheckValues{
			EnvelopeFrom: data.From,
			HeaderFrom:   from,
			Helo:         data.Helo,
			MailData:     string(data.Data),
			Ip:           ip.IP,
		}
		result := validator.RunChecks(ctx, values)
		if result.Reject {
			logrus.Infof("rejecting incoming mail for reason: %v", result.Reason)
			return errors.New(result.Reason)
		}
		subject := parsedMail.Subject
		//TODO: in the future, let users decide what they want to do with quarantined incoming mail; reject or allow.
		if result.Quarantine {
			subject = "[SPAM] " + subject
		}
		// data.To will always have 1 element.
		to := data.To[0]

		resp, err := apiClient.GetMask(context.TODO(), &main_api.GetMaskRequest{MaskAddress: to})
		if err != nil {
			logrus.Errorf("grpc error(GetMask): %v", err)
			return err
		}

		// Silently discard the email
		if !resp.Enabled {
			return nil
		}

		err = mailer.ForwardMail(parsedMail.From[0].Name, to, resp.Email, subject, parsedMail.HTMLBody, parsedMail.TextBody)
		if err != nil {
			logrus.Errorf("mailer err: %v", err)

			//TODO: this shouldn't be a synchronous action, perhaps we can use a message broker here?
			go func() {
				_, innerErr := apiClient.IncrementReceivedCount(context.TODO(), &main_api.IncrementReceivedCountRequest{MaskAddress: to})
				if innerErr != nil {
					logrus.Error("grpc error(IncrementReceivedCount): ", innerErr)
				}
			}()
			return err
		}
		go func() {
			_, innerErr := apiClient.IncrementForwardedCount(context.TODO(), &main_api.IncrementForwardedCountRequest{MaskAddress: to})
			if innerErr != nil {
				logrus.Error("DB error(IncrementForwardedCount): ", innerErr)
			}
		}()
		logrus.Debugf("Forwarded mail to: %v from address: %v", resp.Email, to)
		return nil
	}
}
