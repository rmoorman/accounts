package main

import (
	"net/http"
	pb "accountspb"
	"github.com/coreos/dex/pkg/log"
	"github.com/otsimo/api/apipb"
	"golang.org/x/net/context"
	"gopkg.in/mgo.v2/bson"
)

func handleChangeEmailFunc(o *OtsimoAccounts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			r.ParseForm()
			oldEmail := r.PostFormValue("old_email")
			newEmail := r.PostFormValue("new_email")

			if oldEmail == "" || newEmail == "" || oldEmail == newEmail {
				log.Info("update.go: invalid body")
				writeError(w, http.StatusBadRequest, "invalid body")
				return
			}
			resp, err := o.Dex.ChangeEmail(context.Background(), &pb.ChangeEmailRequest{
				OldEmail: oldEmail,
				NewEmail: newEmail,
			})

			log.Infof("update.go: change email result is %q %v", resp, err)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			id := r.Header.Get("sub")
			if bson.IsObjectIdHex(id) {
				o.Api.UpdateProfile(context.Background(), &apipb.Profile{Id: bson.ObjectIdHex(id), Email: newEmail})
			}

			writeResponseWithBody(w, http.StatusOK, resp)
		} else {
			writeError(w, http.StatusNotFound, "Not Found")
		}
	}
}

func handleChangePasswordFunc(o *OtsimoAccounts) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			r.ParseForm()
			oldPass := r.PostFormValue("old_password")
			newPass := r.PostFormValue("new_password")
			userID := r.PostFormValue("user_id")

			if userID == "" || oldPass == "" || newPass == "" {
				log.Infof("update.go: invalid body '%s'", userID)
				writeError(w, http.StatusBadRequest, "invalid body")
				return
			}
			resp, err := o.Dex.ChangePassword(context.Background(), &pb.ChangePasswordRequest{
				UserId:      userID,
				OldPassword: oldPass,
				NewPassword: newPass,
			})

			log.Infof("update.go: change password result is %q %v", resp, err)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeResponseWithBody(w, http.StatusOK, resp)
		} else {
			writeError(w, http.StatusNotFound, "Not Found")
		}
	}
}
