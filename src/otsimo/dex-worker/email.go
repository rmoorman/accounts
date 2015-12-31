package main

import (
	"encoding/json"

	"github.com/coreos/dex/email"
	"github.com/coreos/dex/pkg/log"
)

const (
	OtsimoEmailerType = "otsimo"
)

func init() {
	email.RegisterEmailerConfigType(OtsimoEmailerType, func() email.EmailerConfig {
		return &OtsimoEmailerConfig{}
	})
}

type OtsimoEmailerConfig struct {
	PrivateAPIKey string `json:"privateAPIKey"`
	PublicAPIKey  string `json:"publicAPIKey"`
	Domain        string `json:"domain"`
}

func (cfg OtsimoEmailerConfig) EmailerType() string {
	return OtsimoEmailerType
}

func (cfg OtsimoEmailerConfig) EmailerID() string {
	return OtsimoEmailerType
}

func (cfg OtsimoEmailerConfig) Emailer() (email.Emailer, error) {
	//todo set grpc connection
	return &otsimoEmailer{}, nil
}

// otsimoEmailerConfig exists to avoid recusion.
type otsimoEmailerConfig OtsimoEmailerConfig

func (cfg *OtsimoEmailerConfig) UnmarshalJSON(data []byte) error {
	mgtmp := otsimoEmailerConfig{}
	err := json.Unmarshal(data, &mgtmp)
	if err != nil {
		return err
	}
	/*
		if mgtmp.PrivateAPIKey == "" {
			return errors.New("must have a privateAPIKey set")
		}

		if mgtmp.PublicAPIKey == "" {
			return errors.New("must have a publicAPIKey set")
		}

		if mgtmp.Domain == "" {
			return errors.New("must have a domain set")
		}
	*/
	*cfg = OtsimoEmailerConfig(mgtmp)
	return nil
}

type otsimoEmailer struct {
}

func (m *otsimoEmailer) SendMail(from, subject, event, data string, to ...string) error {
	/*msg := m.mg.NewMessage(from, subject, text, to...)
	  if html != "" {
	  	msg.SetHtml(html)
	  }
	  mes, id, err := m.mg.Send(msg)
	  if err != nil {
	  	counterEmailSendErr.Add(1)
	  	return err
	  }*/
	log.Infof("SendMail: msgID: %v: %q %s %s", from, subject, event, data)
	return nil
}
