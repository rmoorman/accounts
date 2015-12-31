package main

import (
	"net/http"
	"net/url"

	pb "accountspb"

	"golang.org/x/net/context"
	"github.com/coreos/dex/pkg/log"
)

func handleRegisterFunc(o *OtsimoAccounts) http.HandlerFunc {
	handlePOST := func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		email := r.PostFormValue("username")
		password := r.PostFormValue("password")

		if email == "" || password == "" {
			writeError(w, http.StatusBadRequest, "invalid body")
			return
		}

		resp, err := o.Dex.Register(context.Background(), &pb.RegisterRequest{
			Email: email,
			DisplayName:"",
			Password: password,
		})

		log.Infof("register result of '%s' is %q %v", email, resp, err)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeResponseWithBody(w, http.StatusOK, resp)
	}
	handleGET := func(w http.ResponseWriter, r *http.Request) {
		oac, err := o.Oidc.OAuthClient()
		if err != nil {
			panic("unable to proceed")
		}

		u, err := url.Parse(oac.AuthCodeURL("", "", ""))
		q := u.Query()
		q.Set("register", "1")
		if err != nil {
			panic("unable to proceed")
		}
		u.RawQuery = q.Encode()
		log.Infof("URL: %v", u.String())
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			handlePOST(w, r)
		} else if r.Method == "GET" {
			handleGET(w, r)
		} else {
			writeError(w, http.StatusNotFound, "wrong Http Verb")
		}
	}
}
