package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/go-oidc/oidc"
)

func handleResendFunc(o *OtsimoAccounts, issuerURL, resendURL, cbURL url.URL) http.HandlerFunc {
	trans := &oidc.AuthenticatedTransport{
		TokenRefresher: &oidc.ClientCredsTokenRefresher{
			Issuer:     issuerURL.String(),
			OIDCClient: o.Oidc,
		},
		RoundTripper: http.DefaultTransport,
	}
	hc := &http.Client{Transport: trans}

	return func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		tok := r.Form.Get("jwt")
		q := struct {
			Token       string `json:"token"`
			RedirectURI string `json:"redirectURI"`
		}{
			Token:       tok,
			RedirectURI: cbURL.String(),
		}
		qBytes, err := json.Marshal(&q)
		res, err := hc.Post(resendURL.String(), "application/json", bytes.NewReader(qBytes))
		if err != nil {
			log.Errorf("error requesting email resend:", err)
			writeError(w, http.StatusInternalServerError, "error requesting email resend")
			return
		}

		w.Write([]byte(fmt.Sprintf("Status from Dex: %v", res.Status)))
	}
}
