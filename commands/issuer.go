package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"

	pat "github.com/cloudflare/pat-go"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var (
	// Default policy values
	defaultOriginTokenLimit  = 100
	defaultTokenPolicyWindow = 86400

	// API URIs
	tokenRequestURI           = "/token-request"
	issuerConfigURI           = "/.well-known/token-issuer-directory"
	issuerNameKeyURI          = "/name-key"
	issuerOriginRequestKeyURI = "/origin-token-key"

	// Media types for token requests and response messages
	tokenRequestMediaType  = "message/token-request"
	tokenResponseMediaType = "message/token-response"

	// Token key formats
	legacyTokenKeyMediaType = "message/rsabssa"
)

type IssuerConfig struct {
	TokenWindow      int    `json:"issuer-token-window"`    // policy window
	RequestURI       string `json:"issuer-request-uri"`     // request URI
	RequestKeyURI    string `json:"issuer-request-key-uri"` // per-origin token key
	OriginNameKeyURI string `json:"origin-name-key-uri"`    // origin HPKE configuration URI
}

type TestIssuer struct {
	name              string
	debug             bool
	rateLimitedIssuer *pat.RateLimitedIssuer
	basicIssuer       *pat.BasicPublicIssuer
}

func (i TestIssuer) dumpRequest(label string, w http.ResponseWriter, req *http.Request) error {
	if i.debug {
		reqEnc, err := httputil.DumpRequest(req, false)
		if err != nil {
			return err
		}
		log.Debugln(label+":", string(reqEnc))
	}
	return nil
}

func (i TestIssuer) handleOriginKeyRequest(w http.ResponseWriter, req *http.Request) {
	err := i.dumpRequest("Handling origin key request", w, req)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	contentType := req.Header.Get("Content-Type")
	legacyFormat := false
	if contentType == legacyTokenKeyMediaType {
		// Default to the RSASSA-PSS OID encoding unless the client requests a legacy key
		legacyFormat = true
	}

	origin := req.URL.Query().Get("origin")
	if origin == "" {
		log.Debugln("Returning basic issuance key")
		tokenKeyEnc, err := marshalTokenKey(i.basicIssuer.TokenKey(), legacyFormat)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/rsa-blind-signature-key") // XXX(caw): what content type should we use?
		w.Header().Set("Connection", "close")
		w.Write(tokenKeyEnc)
		return
	}

	log.Debugln("Returning key for origin", origin)
	tokenKey := i.rateLimitedIssuer.OriginTokenKey(origin)
	tokenKeyEnc, err := marshalTokenKey(tokenKey, legacyFormat)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/rsa-blind-signature-key") // XXX(caw): what content type should we use?
	w.Header().Set("Connection", "close")
	w.Write(tokenKeyEnc)
}

func (i TestIssuer) handleNameKeyRequest(w http.ResponseWriter, req *http.Request) {
	err := i.dumpRequest("Handling HPKE config request", w, req)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/issuer-name-key")
	w.Header().Set("Connection", "close")
	w.Write(i.rateLimitedIssuer.NameKey().Marshal())
}

func (i TestIssuer) handleConfigRequest(w http.ResponseWriter, req *http.Request) {
	err := i.dumpRequest("Handling config request", w, req)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	config := IssuerConfig{
		TokenWindow:      defaultTokenPolicyWindow,
		RequestURI:       "https://" + i.name + tokenRequestURI,
		RequestKeyURI:    "https://" + i.name + issuerOriginRequestKeyURI,
		OriginNameKeyURI: "https://" + i.name + issuerNameKeyURI,
	}

	jsonResp, err := json.Marshal(config)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	req.Close = true
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Connection", "close")
	w.Write(jsonResp)
}

func (i TestIssuer) handleIssuanceRequest(w http.ResponseWriter, req *http.Request) {
	err := i.dumpRequest("Handling issuance request", w, req)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	if req.Method != http.MethodPost {
		log.Debugln("Invalid method")
		w.Header().Set("Connection", "close")
		http.Error(w, "Invalid method", 400)
		return
	}
	if req.Header.Get("Content-Type") != tokenRequestMediaType {
		log.Debugln("Invalid content type, expected", tokenRequestMediaType, "got", req.Header.Get("Content-Type"))
		w.Header().Set("Connection", "close")
		http.Error(w, "Invalid Content-Type", 400)
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Debugln("Failed reading request body")
		w.Header().Set("Connection", "close")
		http.Error(w, err.Error(), 400)
		return
	}

	tokenType := binary.BigEndian.Uint16(body)
	if tokenType == pat.RateLimitedTokenType {
		var tokenRequest pat.RateLimitedTokenRequest
		if !tokenRequest.Unmarshal(body) {
			log.Debugln("Failed decoding token request")
			w.Header().Set("Connection", "close")
			http.Error(w, "Failed decoding token request", 400)
			return
		}

		blindSignature, blindRequest, err := i.rateLimitedIssuer.Evaluate(&tokenRequest)
		if err != nil {
			log.Debugln("Token evaluation failed:", err)
			w.Header().Set("Connection", "close")
			http.Error(w, "Token evaluation failed", 400)
			return
		}

		w.Header().Set("content-type", tokenResponseMediaType)
		w.Header().Set("Connection", "close")
		w.Header().Set(headerTokenLimit, strconv.Itoa(defaultOriginTokenLimit))
		w.Header().Set(headerTokenOrigin, marshalStructuredBinary(blindRequest))
		w.Write(blindSignature)
	} else if tokenType == pat.BasicPublicTokenType {
		var tokenRequest pat.BasicPublicTokenRequest
		if !tokenRequest.Unmarshal(body) {
			log.Debugln("Failed decoding token request")
			w.Header().Set("Connection", "close")
			http.Error(w, "Failed decoding token request", 400)
			return
		}

		blindSignature, err := i.basicIssuer.Evaluate(&tokenRequest)
		if err != nil {
			log.Debugln("Token evaluation failed:", err)
			w.Header().Set("Connection", "close")
			http.Error(w, "Token evaluation failed", 400)
			return
		}

		w.Header().Set("content-type", tokenResponseMediaType)
		w.Header().Set("Connection", "close")
		w.Write(blindSignature)
	}
}

type customHandler struct {
	i TestIssuer
}

func (th customHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case issuerConfigURI:
		th.i.handleConfigRequest(w, r)
		break
	case issuerNameKeyURI:
		th.i.handleNameKeyRequest(w, r)
		break
	case issuerOriginRequestKeyURI:
		th.i.handleOriginKeyRequest(w, r)
		break
	case tokenRequestURI:
		th.i.handleIssuanceRequest(w, r)
		break
	default:
		log.Debugln("Unsupported path")
		w.Header().Set("Connection", "close")
		http.Error(w, "Unsupported path", 400)
	}
}

func startIssuer(c *cli.Context) error {
	cert := c.String("cert")
	key := c.String("key")
	port := c.String("port")
	logLevel := c.String("log")
	name := c.String("name")

	if cert == "" {
		log.Fatal("Invalid key material (missing certificate). See README for configuration.")
	}
	if key == "" {
		log.Fatal("Invalid key material (missing private key). See README for configuration.")
	}
	if name == "" {
		log.Fatal("Invalid issuer name. See README for configuration.")
	}
	switch logLevel {
	case "verose":
		log.SetLevel(log.DebugLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	}

	tokenKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	basicIssuer := pat.NewBasicPublicIssuer(tokenKey)
	rateLimitedIssuer := pat.NewRateLimitedIssuer()
	origins := c.StringSlice("origins")
	if len(origins) > 0 {
		for _, origin := range origins {
			rateLimitedIssuer.AddOrigin(origin)
		}
	} else {
		rateLimitedIssuer.AddOrigin("origin.example")
	}

	issuer := TestIssuer{
		name:              name,
		debug:             logLevel == "verbose",
		rateLimitedIssuer: rateLimitedIssuer,
		basicIssuer:       basicIssuer,
	}

	server := &http.Server{
		Addr:           ":" + port,
		Handler:        &customHandler{issuer},
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	server.SetKeepAlivesEnabled(false)

	err = server.ListenAndServeTLS(cert, key)
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
	}
	return err
}
