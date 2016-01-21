package main

import (
	"encoding/json"

	"errors"

	"github.com/coreos/dex/email"
	"github.com/coreos/dex/pkg/log"
	pb "github.com/otsimo/simple-notifications/notificationpb"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
	GrpcUrl string `json:"grpcUrl"`
	UseTls  bool   `json:"useTls"`
	CaCert  string `json:"caCert"`
	Fake    bool   `json:"fake"`
}

func (cfg OtsimoEmailerConfig) EmailerType() string {
	return OtsimoEmailerType
}

func (cfg OtsimoEmailerConfig) EmailerID() string {
	return OtsimoEmailerType
}

func (cfg OtsimoEmailerConfig) Emailer() (email.Emailer, error) {
	var opts []grpc.DialOption
	if cfg.Fake {
		return &otsimoEmailer{fake: true}, nil
	} else {
		if cfg.UseTls {
			auth, err := credentials.NewClientTLSFromFile(cfg.CaCert, "")
			if err != nil {
				panic(err)
			} else {
				opts = append(opts, grpc.WithTransportCredentials(auth))
			}
		} else {
			opts = append(opts, grpc.WithInsecure())
		}
		conn, err := grpc.Dial(cfg.GrpcUrl, opts...)
		if err != nil {
			log.Fatalf("email.go: Error while connection to notification service %v\n", err)
		}
		client := pb.NewNotificationServiceClient(conn)
		return &otsimoEmailer{client: client, fake: false}, nil
	}
}

// otsimoEmailerConfig exists to avoid recusion.
type otsimoEmailerConfig OtsimoEmailerConfig

func (cfg *OtsimoEmailerConfig) UnmarshalJSON(data []byte) error {
	mgtmp := otsimoEmailerConfig{}
	err := json.Unmarshal(data, &mgtmp)
	if err != nil {
		return err
	}
	if mgtmp.GrpcUrl == "" {
		return errors.New("must have a grpcUrl set")
	}

	*cfg = OtsimoEmailerConfig(mgtmp)
	return nil
}

type otsimoEmailer struct {
	fake   bool
	client pb.NotificationServiceClient
}

func (m *otsimoEmailer) SendMail(from, subject, event, data string, to ...string) error {
	email := &pb.Email{
		FromEmail: from,
		Subject:   subject,
		DataJson:  data,
		ToEmail:   to,
	}
	mes := &pb.Message{
		Event:   event,
		Targets: pb.NewTargets(pb.NewEmailTarget(email)),
	}
	if m.fake {
		log.Infof("email.go: email sent: %v", mes)
		return nil
	}
	_, err := m.client.SendMessage(context.Background(), mes)
	if err != nil {
		log.Errorf("email.go: sending email error: %v", err)
	}
	return err
}
