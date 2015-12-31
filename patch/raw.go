package email

import (
	"text/template"
	htmltemplate "html/template"
	"encoding/json"
)

type EmailSender interface {
	SendMail(from, subject, tplName string, data map[string]interface{}, to string) error
	SetGlobalContext(ctx map[string]interface{})
}

type RawEmailer struct {
	emailer   Emailer
	globalCtx map[string]interface{}
}

func (r *RawEmailer)SendMail(from, subject, tplName string, data map[string]interface{}, to string) error {
	for k, v := range r.globalCtx {
		data[k] = v
	}

	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return r.emailer.SendMail(from, subject, tplName, string(b), to)
}

func (r *RawEmailer)SetGlobalContext(ctx map[string]interface{}) {
	r.globalCtx = ctx
}

func NewRawEmailerFromTemplates(textTemplates *template.Template, htmlTemplates *htmltemplate.Template, emailer Emailer) EmailSender {
	return &RawEmailer{
		emailer:       emailer,
	}
}