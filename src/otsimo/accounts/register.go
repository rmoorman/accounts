package main

import (
	pb "accountspb"
	"fmt"
	"net/http"
	"net/url"

	"github.com/coreos/dex/pkg/log"
	"github.com/otsimo/api/apipb"
	"golang.org/x/net/context"
	"gopkg.in/mgo.v2/bson"
)

func handleRegisterFunc(o *OtsimoAccounts) http.HandlerFunc {
	handlePOST := func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		email := r.PostFormValue("username")
		password := r.PostFormValue("password")
		firstName := r.PostFormValue("first_name")
		lastName := r.PostFormValue("last_name")
		language := r.PostFormValue("language")
		if email == "" || password == "" {
			writeError(w, http.StatusBadRequest, "invalid body")
			return
		}
		result, err := registerUser(o, email, password, firstName, lastName, language)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeResponseWithBody(w, http.StatusOK, result.Token)
	}
	handleGET := func(w http.ResponseWriter, r *http.Request) {
		oac, err := o.Oidc.OAuthClient()
		if err != nil {
			log.Errorf("failed to create OAuthClient %v", err)
			writeError(w, http.StatusInternalServerError, err.Error())
		}

		u, err := url.Parse(oac.AuthCodeURL("", "", ""))
		q := u.Query()
		q.Set("register", "1")
		if err != nil {
			log.Errorf("failed to create authCoreURL %v", err)
			writeError(w, http.StatusInternalServerError, err.Error())
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

func registerUser(o *OtsimoAccounts, email, password, firstName, lastName, language string) (*pb.RegisterResponse, error) {
	resp, err := o.Dex.Register(context.Background(), &pb.RegisterRequest{
		Email:       email,
		DisplayName: fmt.Sprintf("%s %s", firstName, lastName),
		Password:    password,
	})

	log.Infof("register.go: register result of '%s' is %q %v", email, resp, err)
	if err != nil {
		return nil, err
	}
	_, errapi := o.Api.AddProfile(context.Background(), &apipb.Profile{
		Id:        bson.ObjectIdHex(resp.UserId),
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Language:  language,
	})
	if errapi != nil {
		//Disable or delete user
		log.Errorf("register.go: failed to add profile %+v", errapi)
		_, err = o.Dex.RemoveUser(context.Background(), &pb.RemoveRequest{Id: resp.UserId, Email: email})
		if err != nil {
			log.Errorf("register.go: Holly FUCK!!: failed to add profile and remove user [error]=%+v [user_id]='%s' [user_email]='%s'", err, resp.UserId, email)
			return nil, err
		}
		return nil, fmt.Errorf("failed to register user, adding to api service failed:%v", errapi)
	}
	return resp, nil
}

/*
Register to DEX
    ->Failed-> return
    ->Success
        -> Add Profile to API
            ->Failed
                -> remove user from DEX
                    -> Failed !!FUCK there is no return
                    -> Success -> return failure
            ->Success-> return
*/
