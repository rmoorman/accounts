package main

import (
	"fmt"
	"net/http"
)

var (
	pathCallback = "/callback"
)

func handleCallbackFunc(o *OtsimoAccounts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			writeError(w, http.StatusBadRequest, "code query param must be set")
			return
		}
		c := o.Oidc
		tok, err := c.ExchangeAuthCode(code)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unable to verify auth code with issuer: %v", err))
			return
		}

		claims, err := tok.Claims()
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unable to construct claims: %v", err))
			return
		}

		s := fmt.Sprintf(`<html><body><p>Token: %v</p><p>Claims: %v </p>
        <a href="/resend?jwt=%s">Resend Verification Email</a>
</body></html>`, tok.Encode(), claims, tok.Encode())
		w.Write([]byte(s))
	}
}
