package main

import (
	"crypto/tls"
	"crypto/x509"
	"expvar"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	pflag "github.com/coreos/dex/pkg/flag"
	"github.com/coreos/dex/pkg/log"
	"github.com/coreos/go-oidc/oidc"
)

var (
	version = "DEV"
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

	cc := oidc.ClientCredentials{
		ID:     *clientID,
		Secret: *clientSecret,
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

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tlsConfig}}

	var cfg oidc.ProviderConfig
	for {
		cfg, err = oidc.FetchProviderConfig(httpClient, *discovery)
		if err == nil {
			break
		}

		sleep := 3 * time.Second
		log.Errorf("Failed fetching provider config, trying again in %v: %v", sleep, err)
		time.Sleep(sleep)
	}

	log.Infof("Fetched provider config from %s: %#v", *discovery, cfg)

	ccfg := oidc.ClientConfig{
		HTTPClient:     httpClient,
		ProviderConfig: cfg,
		Credentials:    cc,
		RedirectURL:    *redirectURL,
	}

	client, err := oidc.NewClient(ccfg)
	if err != nil {
		log.Fatalf("Unable to create Client: %v", err)
	}

	client.SyncProviderConfig(*discovery)
	redirectURLParsed, err := url.Parse(*redirectURL)
	if err != nil {
		log.Fatalf("Unable to parse url from --redirect-url flag: %v", err)
	}
	accounts := NewOtsimoAccounts(client, cc, roots)
	accounts.ConnectToDexService(*connectService)

	hdlr := NewClientHandler(accounts, *discovery, *redirectURLParsed)
	httpsrv := &http.Server{
		Addr:    fmt.Sprintf(":%s", p),
		Handler: hdlr,
	}

	log.Infof("Binding to %s...", httpsrv.Addr)
	log.Fatal(httpsrv.ListenAndServe())
}

func NewClientHandler(o *OtsimoAccounts, issuer string, cbURL url.URL) http.Handler {
	mux := http.NewServeMux()

	issuerURL, err := url.Parse(issuer)
	if err != nil {
		log.Fatalf("Could not parse issuer url: %v", err)
	}

	mux.HandleFunc("/", handleIndex)
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
