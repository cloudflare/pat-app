package commands

import (
	"encoding/binary"
	"encoding/json"
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
	tokenRequestURI           = "/token-request"
	issuerConfigURI           = "/.well-known/token-issuer-directory"
	issuerNameKeyURI          = "/name-key"
	issuerOriginRequestKeyURI = "/origin-token-key"

	// Media types for token requests and response messages
	tokenRequestMediaType  = "message/token-request"
	tokenResponseMediaType = "message/token-response"
)

type IssuerConfig struct {
	TokenWindow      string `json:"issuer-token-window"`    // policy window
	RequestURI       string `json:"issuer-request-uri"`     // request URI
	RequestKeyURI    string `json:"issuer-request-key-uri"` // per-origin token key
	OriginNameKeyURI string `json:"origin-name-key-uri"`    // origin HPKE configuration URI
}

type TestIssuer struct {
	rateLimitedIssuer *pat.RateLimitedIssuer
	basicIssuer       *pat.BasicPublicIssuer
}

func (i TestIssuer) handleOriginKeyRequest(w http.ResponseWriter, req *http.Request) {
	reqEnc, _ := httputil.DumpRequest(req, false)
	log.Debugln("Handling origin key request:", string(reqEnc))

	origin := req.URL.Query().Get("origin")
	if origin == "" {
		log.Debugln("Returning basic issuance key")
		tokenKeyEnc, err := marshalTokenKey(i.basicIssuer.TokenKey())
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/rsa-blind-signature-key") // XXX(caw): what content type should we use?
		w.Write(tokenKeyEnc)
		return
	}

	log.Debugln("Returning key for origin", origin)
	tokenKey := i.rateLimitedIssuer.OriginTokenKey(origin)
	tokenKeyEnc, err := marshalTokenKey(tokenKey)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/rsa-blind-signature-key") // XXX(caw): what content type should we use?
	w.Write(tokenKeyEnc)
}

func (i TestIssuer) handleNameKeyRequest(w http.ResponseWriter, req *http.Request) {
	reqEnc, _ := httputil.DumpRequest(req, false)
	log.Debugln("Handling HPKE config request:", string(reqEnc))

	w.Header().Set("Content-Type", "application/issuer-name-key")
	w.Write(i.rateLimitedIssuer.NameKey().Marshal())
}

func (i TestIssuer) handleConfigRequest(w http.ResponseWriter, req *http.Request) {
	reqEnc, _ := httputil.DumpRequest(req, false)
	log.Debugln("Handling config request:", string(reqEnc))

	resp := make(map[string]string)
	resp["issuer-token-window"] = strconv.Itoa(defaultTokenPolicyWindow)
	resp["issuer-request-uri"] = tokenRequestURI
	resp["issuer-request-key-uri"] = issuerOriginRequestKeyURI
	resp["origin-name-key-uri"] = issuerNameKeyURI

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Internal error", 400)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResp)
}

func (i TestIssuer) handleIssuanceRequest(w http.ResponseWriter, req *http.Request) {
	reqEnc, _ := httputil.DumpRequest(req, false)
	log.Debugln("Handling issuance request:", string(reqEnc))

	if req.Method != http.MethodPost {
		log.Debugln("Invalid method")
		http.Error(w, "Invalid method", 400)
		return
	}
	if req.Header.Get("Content-Type") != tokenRequestMediaType {
		log.Debugln("Invalid content type")
		http.Error(w, "Invalid Content-Type", 400)
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Debugln("Failed reading request body")
		http.Error(w, err.Error(), 400)
		return
	}

	tokenType := binary.BigEndian.Uint16(body)
	if tokenType == pat.RateLimitedTokenType {
		var tokenRequest pat.RateLimitedTokenRequest
		if !tokenRequest.Unmarshal(body) {
			log.Debugln("Failed decoding token request")
			http.Error(w, "Failed decoding token request", 400)
			return
		}

		blindSignature, blindRequest, err := i.rateLimitedIssuer.EvaluateWithoutCheck(&tokenRequest)
		if err != nil {
			log.Debugln("Token evaluation failed:", err)
			http.Error(w, "Token evaluation failed", 400)
			return
		}

		w.Header().Set("content-type", tokenResponseMediaType)
		w.Header().Set(headerTokenLimit, strconv.Itoa(defaultOriginTokenLimit))
		w.Header().Set(headerTokenOrigin, marshalStructuredBinary(blindRequest))
		w.Write(blindSignature)
	} else if tokenType == pat.BasicPublicTokenType {
		var tokenRequest pat.BasicPublicTokenRequest
		if !tokenRequest.Unmarshal(body) {
			log.Debugln("Failed decoding token request")
			http.Error(w, "Failed decoding token request", 400)
			return
		}

		blindSignature, err := i.basicIssuer.Evaluate(&tokenRequest)
		if err != nil {
			log.Debugln("Token evaluation failed:", err)
			http.Error(w, "Token evaluation failed", 400)
			return
		}

		w.Header().Set("content-type", tokenResponseMediaType)
		w.Write(blindSignature)
	}
}

func startIssuer(c *cli.Context) error {
	cert := c.String("cert")
	key := c.String("key")
	port := c.String("port")

	if cert == "" {
		log.Fatal("Invalid key material (missing certificate). See README for configuration.")
	}
	if key == "" {
		log.Fatal("Invalid key material (missing private key). See README for configuration.")
	}

	basicIssuer := pat.NewBasicPublicIssuer()
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
		rateLimitedIssuer: rateLimitedIssuer,
		basicIssuer:       basicIssuer,
	}

	http.HandleFunc(issuerConfigURI, issuer.handleConfigRequest)
	http.HandleFunc(tokenRequestURI, issuer.handleIssuanceRequest)
	http.HandleFunc(issuerNameKeyURI, issuer.handleNameKeyRequest)
	http.HandleFunc(issuerOriginRequestKeyURI, issuer.handleOriginKeyRequest)
	err := http.ListenAndServeTLS(":"+port, cert, key, nil)
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
	}
	return err
}
