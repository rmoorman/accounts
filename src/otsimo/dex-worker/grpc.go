package main

import (
	pb "accountspb"
	"encoding/base64"
	"net"
	"strings"
	"time"
	"fmt"
	"github.com/coreos/dex/connector"
	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/dex/server"
	"github.com/coreos/dex/session"
	"github.com/coreos/dex/user/manager"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oauth2"
	"github.com/coreos/go-oidc/oidc"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"errors"
	"github.com/coreos/dex/user"
	"math/rand"
	"google.golang.org/grpc/grpclog"
	"os"
	golog "log"
)

type grpcServer struct {
	server           *server.Server
	idp              *connector.LocalIdentityProvider
	localConnectorID string
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s + 1:], true
}

func registerFromLocalConnector(userManager *manager.UserManager, connector, email, password string) (string, error) {
	userID, err := userManager.RegisterWithPassword(email, password, connector)
	if err != nil {
		return "", err
	}
	return userID, nil
}

func getJWTToken(ctx context.Context) (jose.JWT, error) {
	md, ok := metadata.FromContext(ctx)
	if !ok {
		return jose.JWT{}, fmt.Errorf("missing metadata")
	}
	var auth []string
	auth, ok = md["Authorization"]
	if !ok || len(auth) == 0 {
		return jose.JWT{}, fmt.Errorf("missing authorization header")
	}
	if len(auth) > 1 {
		return jose.JWT{}, fmt.Errorf("too many authorization header")
	}
	ah := auth[0]
	if len(ah) <= 6 || strings.ToUpper(ah[0:6]) != "BEARER" {
		return jose.JWT{}, errors.New("should be a bearer token")
	}
	val := ah[7:]
	if len(val) == 0 {
		return jose.JWT{}, errors.New("bearer token is empty")
	}
	return jose.ParseJWT(val)
}

func (s *grpcServer) authToken(jwt jose.JWT) (string, *oidc.ClientMetadata, error) {
	ciRepo := s.server.ClientIdentityRepo
	keys, err := s.server.KeyManager.PublicKeys()
	if err != nil {
		log.Errorf("grpc.go: Failed to get keys: %v", err)
		return "", nil, errors.New("errorAccessDenied")
	}
	if len(keys) == 0 {
		log.Error("grpc.go: No keys available for verification client")
		return "", nil, errors.New("errorAccessDenied")
	}

	ok, err := oidc.VerifySignature(jwt, keys)
	if err != nil {
		log.Errorf("grpc.go: Failed to verify signature: %v", err)
		return "", nil, err
	}
	if !ok {
		log.Info("grpc.go: token signature is not verified")
		return "", nil, errors.New("invalid token")
	}

	clientID, err := oidc.VerifyClientClaims(jwt, s.server.IssuerURL.String())
	if err != nil {
		log.Errorf("grpc.go: Failed to verify JWT claims: %v", err)
		return "", nil, errors.New("failed to verify jwt claims token")
	}

	md, err := ciRepo.Metadata(clientID)
	if md == nil || err != nil {
		log.Errorf("grpc.go: Failed to find clientID: %s, error=%v", clientID, err)
		return "", nil, err
	}
	//client must be admin in order to use login and register grpc apis.
	ok, err = ciRepo.IsDexAdmin(clientID)
	if err != nil {
		return "", nil, err
	}

	if !ok {
		log.Infof("grpc.go: Client [%s] is not admin", clientID)
		return "", nil, errors.New("errorAccessDenied")
	}

	log.Debugf("grpc.go: Authenticated token for client ID %s", clientID)
	return clientID, md, nil
}

func (s *grpcServer) Token(userID, clientID string, iat, exp time.Time) (*jose.JWT, string, error) {
	signer, err := s.server.KeyManager.Signer()
	if err != nil {
		log.Errorf("grpc.go: Failed to generate ID token: %v", err)
		return nil, "", oauth2.NewError(oauth2.ErrorServerError)
	}

	user, err := s.server.UserRepo.Get(nil, userID)
	if err != nil {
		log.Errorf("grpc.go: Failed to fetch user %q from repo: %v: ", userID, err)
		return nil, "", oauth2.NewError(oauth2.ErrorServerError)
	}
	claims := oidc.NewClaims(s.server.IssuerURL.String(), userID, clientID, iat, exp)
	user.AddToClaims(claims)

	jwt, err := jose.NewSignedJWT(claims, signer)
	if err != nil {
		log.Errorf("grpc.go: Failed to generate ID token: %v", err)
		return nil, "", oauth2.NewError(oauth2.ErrorServerError)
	}

	refreshToken, err := s.server.RefreshTokenRepo.Create(user.ID, clientID)
	if err != nil {
		log.Errorf("grpc.go: Failed to generate refresh token: %v", err)
		return nil, "", oauth2.NewError(oauth2.ErrorServerError)
	}

	return jwt, refreshToken, nil
}

func (g *grpcServer) Login(ctx context.Context, in *pb.LoginRequest) (*pb.Token, error) {
	jwtClient, err := getJWTToken(ctx)
	if err != nil {
		log.Errorf("grpc.go: getJWTToken error %v", err)
		return nil, err
	}
	clientId, _, err := g.authToken(jwtClient)
	if err != nil {
		log.Errorf("grpc.go: authToken failed error=%v", err)
		return nil, err
	}

	email, password, ok := parseBasicAuth(in.BasicAuth)
	if !ok {
		return nil, errors.New("failed to parse basic auth")
	}

	i, err := g.idp.Identity(email, password)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	jwt, rt, err := g.Token(i.ID, clientId, now, now.Add(session.DefaultSessionValidityWindow))

	if err != nil {
		return nil, err
	}

	log.Infof("grpc.go: token sent: userID=%s email:%s", i.ID, email)

	return &pb.Token{
		AccessToken:  jwt.Encode(),
		TokenType:    "bearer",
		RefreshToken: rt,
	}, nil
}

func (g *grpcServer) Register(ctx context.Context, in *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	jwtClient, err := getJWTToken(ctx)
	if err != nil {
		log.Errorf("grpc.go: getJWTToken error %v", err)
		return nil, err
	}
	clientId, md, err := g.authToken(jwtClient)
	if err != nil {
		log.Errorf("grpc.go: authToken failed error=%v", err)
		return nil, err
	}

	id, err := registerFromLocalConnector(g.server.UserManager, g.localConnectorID, in.Email, in.Password)
	if err != nil {
		return nil, err
	}

	//send email
	g.server.UserEmailer.SendEmailVerification(id, clientId, md.RedirectURLs[0])

	now := time.Now()
	jwt, rt, err := g.Token(id, clientId, now, now.Add(session.DefaultSessionValidityWindow))

	if err != nil {
		return nil, err
	}

	log.Infof("grpc.go: token sent: userID=%s email:%s", id, in.Email)

	return &pb.RegisterResponse{
		UserId: id,
		Token: &pb.Token{
			AccessToken:  jwt.Encode(),
			TokenType:    "bearer",
			RefreshToken: rt,
		},
	}, nil
}

func (g *grpcServer) RemoveUser(ctx context.Context, in *pb.RemoveRequest) (*pb.RemoveResponse, error) {
	jwtClient, err := getJWTToken(ctx)
	if err != nil {
		log.Errorf("grpc.go: getJWTToken error %v", err)
		return nil, err
	}
	_, _, err = g.authToken(jwtClient)
	if err != nil {
		log.Errorf("grpc.go: authToken failed error=%v", err)
		return nil, err
	}

	usr, err := g.server.UserManager.Get(in.Id)
	if err != nil {
		log.Errorf("grpc.go: failed to get user %+v", err)
		return nil, err
	}
	if usr.Email == in.Email {
		return nil, errors.New("given email is different than old one")
	}
	err = g.server.UserRepo.Update(nil, user.User{
		ID: in.Id,
		Email: fmt.Sprintf("$$%s$%s", randStringBytesRmndr(4), in.Email),
		Disabled: false,
	})
	if err != nil {
		log.Errorf("grpc.go: failed to update-remove user %+v", err)
		return nil, err
	}
	return &pb.RemoveResponse{Type:0}, nil
}

func ServeGrpc(cfg *server.ServerConfig, srv *server.Server, grpcUrl string, certFile, keyFile string) {
	var opts []grpc.ServerOption
	if certFile != "" && keyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
		if err != nil {
			log.Fatalf("grpc.go: Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	s := grpc.NewServer(opts...)

	rpcSrv := &grpcServer{
		server: srv,
		idp: &connector.LocalIdentityProvider{
			UserRepo:         srv.UserRepo,
			PasswordInfoRepo: srv.PasswordInfoRepo,
		},
	}

	for _, c := range srv.Connectors {
		if cc, ok := c.(*connector.LocalConnector); ok {
			rpcSrv.localConnectorID = cc.ID()
			break
		}
	}

	grpclog.SetLogger(golog.New(os.Stdout, "", 0))
	pb.RegisterDexServiceServer(s, rpcSrv)

	lis, err := net.Listen("tcp", grpcUrl)
	if err != nil {
		log.Fatalf("grpc.go: failed to listen: %v", err)
	}
	log.Infof("grpc: Grpc server starting on %s", grpcUrl)
	s.Serve(lis)
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytesRmndr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63() % int64(len(letterBytes))]
	}
	return string(b)
}