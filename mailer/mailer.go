package mailer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type Mailer struct {
	token      string
	httpClient *http.Client
}

func New(token string) *Mailer {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 100
	transport.MaxConnsPerHost = 100
	transport.MaxIdleConnsPerHost = 100

	return &Mailer{
		token: token,
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		}}
}

func (m *Mailer) transformRecipients(to []string) []map[string]interface{} {
	data := make([]map[string]interface{}, 0)
	for _, v := range to {
		entry := map[string]interface{}{
			"email_address": map[string]interface{}{
				"address": v,
			},
		}
		data = append(data, entry)
	}
	return data
}

func (m *Mailer) ForwardMail(sender, forwardAddress, subject, htmlBody, textBody string, recipients []string) error {
	body := map[string]interface{}{
		"bounce_address": "bounce@bounce.maskr.app",
		"htmlbody":       htmlBody,
		"textbody":       textBody,
		"subject":        subject,
		"from": map[string]interface{}{
			"address": forwardAddress,
			"name":    sender,
		},
		"to": m.transformRecipients(recipients),
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequest("POST", "https://api.zeptomail.eu/v1.1/email", bytes.NewBuffer(data))
	if err != nil {
		return err

	}
	authHeader := fmt.Sprintf("Zoho-enczapikey %v", m.token)
	request.Header = map[string][]string{
		"Accept":        {"application/json"},
		"Content-Type":  {"application/json"},
		"Authorization": {authHeader},
	}
	resp, err := m.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var res map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&res)
	if resp.StatusCode != 201 {
		errorMessage := fmt.Sprintf("expected status code 201, got: %v with response body: %v", resp.StatusCode, res)
		return errors.New(errorMessage)
	}
	return err
}
