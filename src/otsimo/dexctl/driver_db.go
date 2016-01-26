package main

import (
	"fmt"

	"github.com/coreos/dex/client"
	"github.com/coreos/dex/connector"
	"github.com/coreos/dex/db"
	_ "github.com/coreos/dex/db/postgresql"
	"github.com/coreos/go-oidc/oidc"
	"errors"
	"github.com/coreos/dex/user"
)

func newDBDriver(storage, dsn string) (driver, error) {
	rd := db.GetDriver(storage)
	if rd == nil {
		return nil, fmt.Errorf("Storage driver not found")
	}
	dbc, err := rd.NewWithMap(map[string]interface{}{"url": dsn})
	if err != nil {
		return nil, err
	}

	drv := &dbDriver{
		ciRepo:  dbc.NewClientIdentityRepo(),
		cfgRepo: dbc.NewConnectorConfigRepo(),
		usrRepo:dbc.NewUserRepo(),
	}

	return drv, nil
}

type dbDriver struct {
	ciRepo  client.ClientIdentityRepo
	cfgRepo connector.ConnectorConfigRepo
	usrRepo user.UserRepo
}

func (d *dbDriver) Valid(m *oidc.ClientMetadata) error {
	if len(m.RedirectURLs) == 0 {
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

	if (meta.RedirectURLs[0].Host != "") {
		clientID, err = oidc.GenClientID(meta.RedirectURLs[0].Host)
	}else if (meta.RedirectURLs[0].Scheme != "") {
		clientID, err = oidc.GenClientID(meta.RedirectURLs[0].Scheme)
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
