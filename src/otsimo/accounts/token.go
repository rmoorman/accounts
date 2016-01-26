package main

import (
	"fmt"
	"net/http"

	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
)

type TokenValidator struct {
	accounts *OtsimoAccounts
}

func newTokenValidator(a *OtsimoAccounts) *TokenValidator {
	return &TokenValidator{accounts: a}
}

func (l *TokenValidator) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	log.Info("validating")
	rawToken, err := oidc.ExtractBearerToken(r)
	if err != nil {
		log.Error("token.go: failed to get jwt from header")
		writeError(rw, http.StatusUnauthorized, "missing or invalid token")
		return
	}

	jwt, err := jose.ParseJWT(rawToken)
	if err != nil {
		log.Error("token.go: failed to parse jwt")
		writeError(rw, http.StatusUnauthorized, "missing or invalid token")
		return
	}

	err = l.accounts.Oidc.VerifyJWT(jwt)
	if err != nil {
		log.Errorf("token.go: Failed to verify signature: %v", err)
		writeError(rw, http.StatusUnauthorized, "invalid token")
	}

	claims, err := jwt.Claims()
	if err != nil {
		log.Error("token.go: failed to get claims", err)
		writeError(rw, http.StatusUnauthorized, "missing or invalid token")
		return
	}

	sub, ok, err := claims.StringClaim("sub")
	if err != nil {
		log.Errorf("token.go: failed to parse 'sub' claim: %v", err)
		writeError(rw, http.StatusUnauthorized, "missing or invalid token")
		return
	}
	if !ok || sub == "" {
		log.Error("token.go: missing required 'sub' claim")
		writeError(rw, http.StatusUnauthorized, "missing or invalid token")
		return
	}
	fmt.Println("token.go: verified token for", sub)
	r.Header.Set("sub", sub)
	next(rw, r)
}
