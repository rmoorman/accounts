package main

import (
	"errors"

	"github.com/coreos/dex/client"
	"github.com/coreos/dex/connector"
	"github.com/coreos/dex/db"
	"github.com/coreos/dex/user"
	"github.com/coreos/go-oidc/oidc"
)

func newDBDriver(dsn string) (driver, error) {
	dbc, err := db.NewConnection(db.Config{DSN: dsn})
	if err != nil {
		return nil, err
	}

	drv := &dbDriver{
		ciRepo:  db.NewClientIdentityRepo(dbc),
		cfgRepo: db.NewConnectorConfigRepo(dbc),
		usrRepo: db.NewUserRepo(dbc),
	}
	return drv, nil
}

type dbDriver struct {
	ciRepo  client.ClientIdentityRepo
	cfgRepo *db.ConnectorConfigRepo
	usrRepo user.UserRepo
}

func (d *dbDriver) Valid(m *oidc.ClientMetadata) error {
	if len(m.RedirectURIs) == 0 {
		return errors.New("zero redirect URLs")
	}

	return nil
}

func (d *dbDriver) NewClient(meta oidc.ClientMetadata, admin bool) (*oidc.ClientCredentials, error) {
	if err := d.Valid(&meta); err != nil {
		return nil, err
	}
	var clientID string
	var err error

	if meta.RedirectURIs[0].Host != "" {
		clientID, err = oidc.GenClientID(meta.RedirectURIs[0].Host)
	} else if meta.RedirectURIs[0].Scheme != "" {
		clientID, err = oidc.GenClientID(meta.RedirectURIs[0].Scheme)
	}
	if err != nil {
		return nil, err
	}
	if clientID == "" {
		return nil, errors.New("invalid first redirect URL")
	}

	cc, err := d.ciRepo.New(clientID, meta)
	if err != nil {
		return nil, err
	}

	if admin {
		d.ciRepo.SetDexAdmin(clientID, admin)
	}

	return cc, nil
}

func (d *dbDriver) ConnectorConfigs() ([]connector.ConnectorConfig, error) {
	return d.cfgRepo.All()
}

func (d *dbDriver) SetConnectorConfigs(cfgs []connector.ConnectorConfig) error {
	return d.cfgRepo.Set(cfgs)
}

func (d *dbDriver) MakeAdmin(email string) error {
	user, err := d.usrRepo.GetByEmail(nil, email)
	if err != nil {
		return err
	}
	user.Admin = true
	return d.usrRepo.Update(nil, user)
}
