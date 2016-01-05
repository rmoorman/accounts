package main

import (
	pb "accountspb"
	"crypto/x509"
	"encoding/json"
	"net/http"

	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
	"github.com/otsimo/api/apipb"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type OtsimoAccounts struct {
	Dex         pb.DexServiceClient
	Api         apipb.ApiServiceClient
	Oidc        *oidc.Client
	Credentials oidc.ClientCredentials
	roots       *x509.CertPool
}

func (c *OtsimoAccounts) ConnectToServices(dexServiceUrl, apiServiceUrl string) {
	jwt, err := c.Oidc.ClientCredsToken(oidc.DefaultScope)
	if err != nil {
		panic(err)
	}

	jwtCreds := NewOauthAccess(&jwt)
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

func NewOtsimoAccounts(client *oidc.Client, cc oidc.ClientCredentials, roots *x509.CertPool) *OtsimoAccounts {
	oa := &OtsimoAccounts{
		Oidc:        client,
		Credentials: cc,
		roots:       roots,
	}
	return oa
}

// oauthAccess supplies credentials from a given token.
type oauthAccess struct {
	Token      jose.JWT
	RequireTLS bool
}

// NewOauthAccess constructs the credentials using a given token.
func NewOauthAccess(token *jose.JWT) oauthAccess {
	return oauthAccess{Token: *token, RequireTLS: true}
}

func (oa *oauthAccess) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"Authorization": "Bearer" + " " + oa.Token.Encode(),
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
