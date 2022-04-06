package commands

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	pat "github.com/cloudflare/pat-go"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var (
	// WWW-Authenticate authorization challenge attributes
	authorizationAttributeChallenge = "challenge"
	authorizationAttributeMaxAge    = "max-age"
	authorizationAttributeTokenKey  = "token-key"
	authorizationAttributeNameKey   = "origin-name-key"

	// Headers clients can send to control the types of token challenges sent
	headerTokenAttributeNoninteractive = "Sec-Token-Attribute-Non-Interactive"
	headerTokenAttributeCrossOrigin    = "Sec-Token-Attribute-Cross-Origin"
	headerTokenAttributeChallengeCount = "Sec-Token-Attribute-Count"
	headerTokenType                    = "Sec-CH-Token-Type" // XXX(caw): string for now, but this should be an sf-list of sf-integer values

	// Type of authorization token
	privateTokenType = "PrivateToken"

	// Test resource to load upon token success
	testResource = "https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html"
)

type TestOrigin struct {
	issuerName            string
	originName            string
	validationKeyEnc      []byte // Encoding of validation public key
	validationKey         *rsa.PublicKey
	basicValidationKeyEnc []byte // Encoding of validation public key
	basicValidationKey    *rsa.PublicKey
	originNameKey         pat.PublicNameKey

	// Map from challenge hash to list of outstanding challenges
	challenges map[string][]pat.TokenChallenge
}

func (o TestOrigin) CreateChallenge(req *http.Request) (string, string) {
	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)
	originInfo := []string{o.originName, "example.com"}

	if req.Header.Get(headerTokenAttributeNoninteractive) != "" || req.URL.Query().Get("noninteractive") != "" {
		// If the client requested a non-interactive token, then clear out the nonce slot
		nonce = []byte{} // empty slice
	}
	if req.Header.Get(headerTokenAttributeCrossOrigin) != "" || req.URL.Query().Get("crossorigin") != "" {
		// If the client requested a cross-origin token, then clear out the origin slot
		originInfo = nil
	}

	tokenKey := base64.URLEncoding.EncodeToString(o.validationKeyEnc)
	tokenType := pat.RateLimitedTokenType // default
	if req.Header.Get(headerTokenType) != "" || req.URL.Query().Get("type") != "" {
		tokenTypeValue, err := strconv.Atoi(req.Header.Get(headerTokenType))
		if err == nil {
			if tokenTypeValue == int(pat.BasicPublicTokenType) {
				tokenType = pat.BasicPublicTokenType
				tokenKey = base64.URLEncoding.EncodeToString(o.basicValidationKeyEnc)
			}
		} else {
			tokenTypeValue, err = strconv.Atoi(req.URL.Query().Get("type"))
			if err == nil {
				if tokenTypeValue == int(pat.BasicPublicTokenType) {
					tokenType = pat.BasicPublicTokenType
					tokenKey = base64.URLEncoding.EncodeToString(o.basicValidationKeyEnc)
				}
			}
		}
	}

	challenge := pat.TokenChallenge{
		TokenType:       tokenType,
		IssuerName:      o.issuerName,
		OriginInfo:      originInfo,
		RedemptionNonce: nonce,
	}

	// Add to the running list of challenges
	challengeEnc := challenge.Marshal()
	context := sha256.Sum256(challengeEnc)
	contextEnc := hex.EncodeToString(context[:])
	_, ok := o.challenges[contextEnc]
	if !ok {
		o.challenges[contextEnc] = make([]pat.TokenChallenge, 0)
	}
	o.challenges[contextEnc] = append(o.challenges[contextEnc], challenge)
	log.Debugln("Adding challenge context", contextEnc)

	return base64.URLEncoding.EncodeToString(challengeEnc), tokenKey
}

func (o TestOrigin) handleRequest(w http.ResponseWriter, req *http.Request) {
	reqEnc, _ := httputil.DumpRequest(req, false)
	log.Debugln("Handling request:", string(reqEnc))

	// If the Authorization header is empty, challenge the client for a token
	if req.Header.Get("Authorization") == "" {
		log.Debugln("Missing authorization header. Replying with challenge.")

		count := 1
		if countReq := req.Header.Get(headerTokenAttributeChallengeCount); countReq != "" {
			countVal, err := strconv.Atoi(countReq)
			if err == nil && countVal > 0 && countVal < 10 {
				// These bounds are arbitrary
				count = countVal
			}
		}
		challengeList := ""
		for i := 0; i < count; i++ {
			challengeEnc, tokenKeyEnc := o.CreateChallenge(req)
			challengeString := authorizationAttributeChallenge + "=" + challengeEnc
			issuerKeyString := authorizationAttributeTokenKey + "=" + tokenKeyEnc
			maxAgeString := authorizationAttributeMaxAge + "=" + "10"
			originNameKeyString := authorizationAttributeNameKey + "=" + base64.URLEncoding.EncodeToString(o.originNameKey.Marshal()) // This might be ignored by clients
			challengeList = challengeList + privateTokenType + " " + challengeString + ", " + issuerKeyString + "," + originNameKeyString + ", " + maxAgeString
		}

		w.Header().Set("WWW-Authenticate", challengeList)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	authValue := req.Header.Get("Authorization")
	tokenPrefix := privateTokenType + " " + "token="
	if !strings.HasPrefix(authValue, tokenPrefix) {
		log.Debugln("Authorization header missing 'PrivateToken token=' prefix")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	tokenValueEnc := strings.SplitAfter(authValue, tokenPrefix)[1] // XXX(caw): there's probably a better way to parse this out
	tokenValue, err := base64.URLEncoding.DecodeString(tokenValueEnc)
	if err != nil {
		log.Debugln("Failed reading Authorization header token value")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	token, err := pat.UnmarshalToken(tokenValue)
	if err != nil {
		log.Debugln("Failed decoding Token")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	tokenContextEnc := hex.EncodeToString(token.Context)
	challengeList, ok := o.challenges[tokenContextEnc]
	if !ok {
		log.Debugln("No outstanding challenge matching context", tokenContextEnc)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	// Consume the first matching challenge
	challenge := challengeList[0]
	o.challenges[tokenContextEnc] = o.challenges[tokenContextEnc][1:]
	log.Debugln("Consuming challenge context", tokenContextEnc)
	log.Debugln("Remainder matching challenge set size", len(o.challenges[tokenContextEnc]))
	if len(o.challenges[tokenContextEnc]) == 0 {
		delete(o.challenges, tokenContextEnc)
	}

	authInput := token.AuthenticatorInput()
	key := o.validationKey
	if challenge.TokenType == pat.BasicPublicTokenType {
		key = o.basicValidationKey
	}

	hash := sha512.New384()
	hash.Write(authInput)
	digest := hash.Sum(nil)
	err = rsa.VerifyPSS(key, crypto.SHA384, digest, token.Authenticator, &rsa.PSSOptions{
		Hash:       crypto.SHA384,
		SaltLength: crypto.SHA384.Size(),
	})
	if err != nil {
		// Token validation failed
		log.Debugln("Token validation failed", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	httpClient := &http.Client{}
	resourceReq, err := http.NewRequest(http.MethodGet, testResource, nil)
	if err != nil {
		log.Debugln(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resourceReq.Header.Add("Authorization", "PrivateToken token="+base64.URLEncoding.EncodeToString(token.Marshal()))
	resp, err := httpClient.Do(resourceReq)
	if err != nil {
		log.Debugln(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Debugln(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(body)
}

func startOrigin(c *cli.Context) error {
	cert := c.String("cert")
	key := c.String("key")
	port := c.String("port")
	issuer := c.String("issuer")
	name := c.String("name")
	logLevel := c.String("log")

	if cert == "" {
		log.Fatal("Invalid key material (missing certificate). See README for configuration.")
	}
	if key == "" {
		log.Fatal("Invalid key material (missing private key). See README for configuration.")
	}
	if issuer == "" {
		log.Fatal("Invalid issuer. See README for configuration.")
	}
	if name == "" {
		log.Fatal("Invalid origin name. See README for configuration.")
	}

	switch logLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	}

	issuerConfig, err := fetchIssuerConfig(issuer)
	if err != nil {
		return err
	}
	requestKeyURI, err := composeURL(issuer, issuerConfig.RequestKeyURI)
	if err != nil {
		return err
	}
	publicKeyEnc, publicKey, err := fetchOriginTokenKey(requestKeyURI, name)
	if err != nil {
		return err
	}
	basicKeyEnc, basicKey, err := fetchOriginTokenKey(requestKeyURI, "")
	if err != nil {
		return err
	}
	nameKeyURI, err := composeURL(issuer, issuerConfig.OriginNameKeyURI)
	if err != nil {
		return err
	}
	originNameKey, err := fetchIssuerNameKey(nameKeyURI)
	if err != nil {
		return err
	}

	log.Debugln("Token verification key:", hex.EncodeToString(publicKeyEnc))

	origin := TestOrigin{
		issuerName:            issuer,
		originName:            name,
		originNameKey:         originNameKey,
		validationKeyEnc:      publicKeyEnc,
		validationKey:         publicKey,
		basicValidationKeyEnc: basicKeyEnc,
		basicValidationKey:    basicKey,
		challenges:            make(map[string][]pat.TokenChallenge),
	}

	http.HandleFunc("/", origin.handleRequest)
	err = http.ListenAndServeTLS(":"+port, cert, key, nil)
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
	}
	return err
}
