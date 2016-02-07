package main

import (
	"crypto/tls"
	"crypto/x509"
	"expvar"
	"flag"
	"fmt"
	"io/ioutil"
	golog "log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/codegangsta/negroni"
	pflag "github.com/coreos/dex/pkg/flag"
	"github.com/coreos/dex/pkg/log"
)

var (
	version = "DEV"
	XRealIP = "X-Real-IP"
	XForwardedFor = "X-Forwarded-For"
)

func init() {
	versionVar := expvar.NewString("dex.version")
	versionVar.Set(version)
}

func main() {
	fs := flag.NewFlagSet("otsimo-accounts", flag.ExitOnError)
	listen := fs.String("listen", "http://127.0.0.1:18856", "")
	redirectURL := fs.String("redirect-url", "http://127.0.0.1:18856/callback", "")
	clientID := fs.String("client-id", "", "")
	clientSecret := fs.String("client-secret", "", "")
	caFile := fs.String("trusted-ca-file", "", "the TLS CA file, if empty then the host's root CA will be used")

	discovery := fs.String("discovery", "https://connect.otsimo.com", "")
	connectService := fs.String("dex", "127.0.0.1:18849", "Otsimo connect grpc url")
	apiService := fs.String("api", "127.0.0.1:18854", "Otsimo api grpc url")

	logDebug := fs.Bool("log-debug", false, "log debug-level information")
	logTimestamps := fs.Bool("log-timestamps", false, "prefix log lines with timestamps")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if err := pflag.SetFlagsFromEnv(fs, "OTSIMO_ACCOUNTS"); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if *logDebug {
		log.EnableDebug()
	}
	if *logTimestamps {
		log.EnableTimestamps()
	}

	if *clientID == "" {
		log.Fatal("--client-id must be set")
	}

	if *clientSecret == "" {
		log.Fatal("--client-secret must be set")
	}

	l, err := url.Parse(*listen)
	if err != nil {
		log.Fatalf("Unable to use --listen flag: %v", err)
	}

	_, p, err := net.SplitHostPort(l.Host)
	if err != nil {
		log.Fatalf("Unable to parse host from --listen flag: %v", err)
	}
	var tlsConfig tls.Config
	var roots *x509.CertPool
	if *caFile != "" {
		roots = x509.NewCertPool()
		pemBlock, err := ioutil.ReadFile(*caFile)
		if err != nil {
			log.Fatalf("Unable to read ca file: %v", err)
		}
		roots.AppendCertsFromPEM(pemBlock)
		tlsConfig.RootCAs = roots
	}
	client, tokenMan := NewClient(*clientID, *clientSecret, *discovery, *redirectURL, &tlsConfig)
	redirectURLParsed, err := url.Parse(*redirectURL)
	if err != nil {
		log.Fatalf("Unable to parse url from --redirect-url flag: %v", err)
	}
	accounts := NewOtsimoAccounts(client, tokenMan, roots)
	accounts.ConnectToServices(*connectService, *apiService)

	mux := NewClientHandler(accounts, *discovery, *redirectURLParsed)

	mux.Handle("/update/password", negroni.New(
		newTokenValidator(accounts),
		negroni.Wrap(handleChangePasswordFunc(accounts)),
	))

	mux.Handle("/update/email", negroni.New(
		newTokenValidator(accounts),
		negroni.Wrap(handleChangeEmailFunc(accounts)),
	))

	n := negroni.New(negroni.NewRecovery(), NewLogger())
	n.UseHandler(mux)
	log.Infof("Binding to :%s...", p)
	//TODO(sercan) add TLS option
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", p), n))
}

func NewClientHandler(o *OtsimoAccounts, issuer string, cbURL url.URL) *http.ServeMux {
	mux := http.NewServeMux()

	issuerURL, err := url.Parse(issuer)
	if err != nil {
		log.Fatalf("Could not parse issuer url: %v", err)
	}

	//mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/login", handleLoginFunc(o))
	mux.HandleFunc("/register", handleRegisterFunc(o))
	mux.HandleFunc(pathCallback, handleCallbackFunc(o))

	resendURL := *issuerURL
	resendURL.Path = "/resend-verify-email"

	mux.HandleFunc("/resend", handleResendFunc(o, *issuerURL, resendURL, cbURL))
	return mux
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://otsimo.com", http.StatusFound)
	//	w.Write([]byte("<a href='/login'>login</a>"))
	//	w.Write([]byte("<br>"))
	//	w.Write([]byte("<a href='/register'>register</a>"))
}

// Logger is a middleware handler that logs the request as it goes in and the response as it goes out.
type Logger struct {
	// Logger inherits from log.Logger used to log messages with the Logger middleware
	*golog.Logger
}

// NewLogger returns a new Logger instance
func NewLogger() *Logger {
	return &Logger{golog.New(os.Stdout, "", 0)}
}

func (l *Logger) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	start := time.Now()

	url := *r.URL
	next(rw, r)

	res := rw.(negroni.ResponseWriter)
	buf := writeLog(r, url, start, res.Status(), res.Size())
	l.Output(2, string(buf))
}

func writeLog(req *http.Request, url url.URL, ts time.Time, status int, size int) []byte {
	username := "-"
	if url.User != nil {
		if name := url.User.Username(); name != "" {
			username = name
		}
	}

	host, _, err := net.SplitHostPort(req.RemoteAddr)

	if err != nil {
		host = req.RemoteAddr
	}

	uri := url.RequestURI()

	buf := make([]byte, 0, 3 * (len(host) + len(username) + len(req.Method) + len(uri) + len(req.Proto) + 50) / 2)
	buf = append(buf, host...)
	buf = append(buf, " - "...)
	buf = append(buf, username...)
	buf = append(buf, " ["...)
	buf = append(buf, ts.Format("02/Jan/2006:15:04:05 -0700")...)
	buf = append(buf, `] "`...)
	buf = append(buf, req.Method...)
	buf = append(buf, " "...)
	buf = appendQuoted(buf, uri)
	buf = append(buf, " "...)
	buf = append(buf, req.Proto...)
	buf = append(buf, `" `...)
	buf = append(buf, strconv.Itoa(status)...)
	buf = append(buf, " "...)
	buf = append(buf, strconv.Itoa(size)...)
	return buf
}

const lowerhex = "0123456789abcdef"

func appendQuoted(buf []byte, s string) []byte {
	var runeTmp [utf8.UTFMax]byte
	for width := 0; len(s) > 0; s = s[width:] {
		r := rune(s[0])
		width = 1
		if r >= utf8.RuneSelf {
			r, width = utf8.DecodeRuneInString(s)
		}
		if width == 1 && r == utf8.RuneError {
			buf = append(buf, `\x`...)
			buf = append(buf, lowerhex[s[0] >> 4])
			buf = append(buf, lowerhex[s[0] & 0xF])
			continue
		}
		if r == rune('"') || r == '\\' {
			// always backslashed
			buf = append(buf, '\\')
			buf = append(buf, byte(r))
			continue
		}
		if strconv.IsPrint(r) {
			n := utf8.EncodeRune(runeTmp[:], r)
			buf = append(buf, runeTmp[:n]...)
			continue
		}
		switch r {
		case '\a':
			buf = append(buf, `\a`...)
		case '\b':
			buf = append(buf, `\b`...)
		case '\f':
			buf = append(buf, `\f`...)
		case '\n':
			buf = append(buf, `\n`...)
		case '\r':
			buf = append(buf, `\r`...)
		case '\t':
			buf = append(buf, `\t`...)
		case '\v':
			buf = append(buf, `\v`...)
		default:
			switch {
			case r < ' ':
				buf = append(buf, `\x`...)
				buf = append(buf, lowerhex[s[0] >> 4])
				buf = append(buf, lowerhex[s[0] & 0xF])
			case r > utf8.MaxRune:
				r = 0xFFFD
				fallthrough
			case r < 0x10000:
				buf = append(buf, `\u`...)
				for s := 12; s >= 0; s -= 4 {
					buf = append(buf, lowerhex[r >> uint(s) & 0xF])
				}
			default:
				buf = append(buf, `\U`...)
				for s := 28; s >= 0; s -= 4 {
					buf = append(buf, lowerhex[r >> uint(s) & 0xF])
				}
			}
		}
	}
	return buf

}
