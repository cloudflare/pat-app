package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strconv"

	pat "github.com/cloudflare/pat-go"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var (
	// Default policy values
	defaultOriginTokenLimit  = 100
	defaultTokenPolicyWindow = 86400

	// API URIs
	tokenRequestURI   = "/token-request"
	issuerConfigURI   = "/.well-known/token-issuer-directory"
	issuerEncapKeyURI = "/issuer-encap-key"

	// Media types for token requests and response messages
	tokenRequestMediaType  = "message/token-request"
	tokenResponseMediaType = "message/token-response"
)

type IssuerTokenKey struct {
	TokenType int    `json:"token-type"`
	TokenKey  string `json:"token-key"`
}

type IssuerConfig struct {
	TokenWindow       int              `json:"issuer-token-window"`  // policy window
	RequestURI        string           `json:"issuer-request-uri"`   // request URI
	TokenKeys         []IssuerTokenKey `json:"token-keys"`           // per-origin token key
	IssuerEncapKeyURI string           `json:"issuer-encap-key-uri"` // issuer encapsulation key URI
}

type Issuer struct {
	name              string
	debug             bool
	rateLimitedIssuer *pat.RateLimitedIssuer
	basicIssuer       *pat.BasicPublicIssuer
}

func (i Issuer) dumpRequest(label string, w http.ResponseWriter, req *http.Request) error {
	if i.debug {
		reqEnc, err := httputil.DumpRequest(req, false)
		if err != nil {
			return err
		}
		log.Debugln(label+":", string(reqEnc))
	}
	return nil
}

func (i Issuer) handleNameKeyRequest(w http.ResponseWriter, req *http.Request) {
	err := i.dumpRequest("Handling HPKE config request", w, req)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/issuer-name-key")
	w.Header().Set("Connection", "close")
	w.Write(i.rateLimitedIssuer.NameKey().Marshal())
}

func (i Issuer) handleConfigRequest(w http.ResponseWriter, req *http.Request) {
	err := i.dumpRequest("Handling config request", w, req)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	basicTokenKeyEnc, err := marshalTokenKey(i.basicIssuer.TokenKey(), false)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	rateLimitedTokenKeyEnc, err := marshalTokenKey(i.rateLimitedIssuer.TokenKey(), false)
	if err != nil {
		http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
		return
	}

	tokenKeys := make([]IssuerTokenKey, 0)
	tokenKeys = append(tokenKeys, IssuerTokenKey{
		TokenType: int(pat.BasicPublicTokenType),
		TokenKey:  base64.URLEncoding.EncodeToString(basicTokenKeyEnc),
	})
	tokenKeys = append(tokenKeys, IssuerTokenKey{
		TokenType: int(pat.RateLimitedTokenType),
		TokenKey:  base64.URLEncoding.EncodeToString(rateLimitedTokenKeyEnc),
	})

	config := IssuerConfig{
		TokenWindow:       defaultTokenPolicyWindow,
		RequestURI:        "https://" + i.name + tokenRequestURI,
		IssuerEncapKeyURI: "https://" + i.name + issuerEncapKeyURI,
		TokenKeys:         tokenKeys,
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

func (i Issuer) handleIssuanceRequest(w http.ResponseWriter, req *http.Request) {
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

		tokenResponse, blindRequest, err := i.rateLimitedIssuer.Evaluate(&tokenRequest)
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
		w.Write(tokenResponse)
	} else if tokenType == pat.BasicPublicTokenType {
		var tokenRequest pat.BasicPublicTokenRequest
		if !tokenRequest.Unmarshal(body) {
			log.Debugln("Failed decoding token request")
			w.Header().Set("Connection", "close")
			http.Error(w, "Failed decoding token request", 400)
			return
		}

		tokenResponse, err := i.basicIssuer.Evaluate(&tokenRequest)
		if err != nil {
			log.Debugln("Token evaluation failed:", err)
			w.Header().Set("Connection", "close")
			http.Error(w, "Token evaluation failed", 400)
			return
		}

		w.Header().Set("content-type", tokenResponseMediaType)
		w.Header().Set("Connection", "close")
		w.Write(tokenResponse)
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

	// XXX(caw): key size is a function of the token issuace protocol
	tokenKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	basicIssuer := pat.NewBasicPublicIssuer(tokenKey)
	rateLimitedIssuer := pat.NewRateLimitedIssuer(tokenKey)
	origins := c.StringSlice("origins")
	if len(origins) > 0 {
		for _, origin := range origins {
			rateLimitedIssuer.AddOrigin(origin)
		}
	} else {
		rateLimitedIssuer.AddOrigin("origin.example")
	}

	issuer := Issuer{
		name:              name,
		debug:             logLevel == "verbose",
		rateLimitedIssuer: rateLimitedIssuer,
		basicIssuer:       basicIssuer,
	}

	http.HandleFunc(issuerConfigURI, issuer.handleConfigRequest)
	http.HandleFunc(tokenRequestURI, issuer.handleIssuanceRequest)
	http.HandleFunc(issuerEncapKeyURI, issuer.handleNameKeyRequest)
	err = http.ListenAndServeTLS(":"+port, cert, key, nil)
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
	}
	return err
}
