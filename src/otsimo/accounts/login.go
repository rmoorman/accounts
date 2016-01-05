package main

import (
	pb "accountspb"
	"encoding/base64"
	"net/http"
	"net/url"

	"github.com/coreos/dex/pkg/log"
	"golang.org/x/net/context"
)

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func handleLoginFunc(o *OtsimoAccounts) http.HandlerFunc {
	handlePOST := func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		username := r.PostFormValue("username")
		password := r.PostFormValue("password")
		grant_type := r.PostFormValue("grant_type")

		if username == "" || password == "" || grant_type == "" {
			writeError(w, http.StatusBadRequest, "invalid body")
			return
		}

		resp, err := o.Dex.Login(context.Background(), &pb.LoginRequest{
			GrantType: grant_type,
			BasicAuth: "Basic " + basicAuth(username, password),
		})
		log.Infof("login.go: login result of '%s' is %q %v", username, resp, err)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeResponseWithBody(w, http.StatusOK, resp)
	}
	handleGET := func(w http.ResponseWriter, r *http.Request) {
		oac, err := o.Oidc.OAuthClient()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unabled create oauth client")
			return
		}
		u, err := url.Parse(oac.AuthCodeURL("", "", ""))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "unabled create auth code url")
			return
		}
		http.Redirect(w, r, u.String(), http.StatusFound)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			handlePOST(w, r)
		} else if r.Method == "GET" {
			handleGET(w, r)
		} else {
			writeError(w, http.StatusNotFound, "wrong HTTP Verb")
		}
	}
}
