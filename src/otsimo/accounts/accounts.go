package main

import (
	pb "accountspb"
	"crypto/x509"
	"encoding/json"
	"net/http"

	"github.com/coreos/dex/pkg/log"
	"github.com/otsimo/api/apipb"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type OtsimoAccounts struct {
	Dex   pb.DexServiceClient
	Api   apipb.ApiServiceClient
	Oidc  *Client
	roots *x509.CertPool
	tm    *ClientCredsTokenManager
}

func (c *OtsimoAccounts) ConnectToServices(dexServiceUrl, apiServiceUrl string) {
	jwtCreds := NewOauthAccess(c.tm)

	var opts []grpc.DialOption
	if c.roots != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(c.roots, "")))
	} else {
		jwtCreds.RequireTLS = false
		opts = append(opts, grpc.WithInsecure())
	}
	opts = append(opts, grpc.WithPerRPCCredentials(&jwtCreds))
	conn, err := grpc.Dial(dexServiceUrl, opts...)
	if err != nil {
		log.Fatalf("Error while connection to dex service %v\n", err)
	}
	c.Dex = pb.NewDexServiceClient(conn)

	apiConn, err := grpc.Dial(apiServiceUrl, opts...)
	if err != nil {
		log.Fatalf("Error while connection to api service %v\n", err)
	}
	c.Api = apipb.NewApiServiceClient(apiConn)
}

func NewOtsimoAccounts(client *Client, tm *ClientCredsTokenManager, roots *x509.CertPool) *OtsimoAccounts {
	oa := &OtsimoAccounts{
		Oidc:  client,
		roots: roots,
		tm:    tm,
	}
	return oa
}

// oauthAccess supplies credentials from a given token.
type oauthAccess struct {
	tm         *ClientCredsTokenManager
	RequireTLS bool
}

// NewOauthAccess constructs the credentials using a given token.
func NewOauthAccess(tm *ClientCredsTokenManager) oauthAccess {
	return oauthAccess{tm: tm, RequireTLS: true}
}

func (oa *oauthAccess) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"Authorization": "Bearer" + " " + oa.tm.Token.Encode(),
	}, nil
}

func (oa *oauthAccess) RequireTransportSecurity() bool {
	return oa.RequireTLS
}

func writeResponseWithBody(w http.ResponseWriter, code int, resp interface{}) {
	enc, err := json.Marshal(resp)
	if err != nil {
		log.Errorf("Failed JSON-encoding HTTP response: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		if _, err = w.Write([]byte(`{"error":"Failed JSON-encoding HTTP response"}`)); err != nil {
			log.Errorf("Failed writing HTTP response: %v", err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if _, err = w.Write(enc); err != nil {
		log.Errorf("Failed writing HTTP response: %v", err)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	e := struct {
		Error string `json:"error"`
	}{
		Error: msg,
	}
	b, err := json.Marshal(e)
	if err != nil {
		log.Errorf("Failed marshaling %#v to JSON: %v", e, err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(b)
}
