package commands

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	pat "github.com/cloudflare/pat-go"
	"github.com/urfave/cli"
	"golang.org/x/crypto/cryptobyte"
)

var (
	// WWW-Authenticate authorization challenge attributes
	authorizationAttributeChallenge = "challenge"
	authorizationAttributeMaxAge    = "max-age"
	authorizationAttributeIssuerKey = "issuer-key"
	authorizationAttributeNameKey   = "origin-name-key"

	// Headers clients can send to control the types of token challenges sent
	headerTokenAttributeNoninteractive = "Sec-Token-Attribute-Non-Interactive"
	headerTokenAttributeCrossOrigin    = "Sec-Token-Attribute-Cross-Origin"
	headerTokenAttributeChallengeCount = "Sec-Token-Attribute-Count"

	// Type of authorization token
	privateTokenType = "PrivateToken"

	// Test resource to load upon token success
	testResource = "https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html"
)

// struct {
//     uint16_t token_type;
//     opaque issuer_name<1..2^16-1>;
//     opaque redemption_nonce<0..32>;
//     opaque origin_name<0..2^16-1>;
// } TokenChallenge;

type TokenChallenge struct {
	tokenType       uint16
	issuerName      string
	redemptionNonce []byte
	originName      string
}

func (c TokenChallenge) Marshal() []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(c.tokenType)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(c.issuerName))
	})
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(c.redemptionNonce)
	})
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte(c.originName))
	})
	return b.BytesOrPanic()
}

func UnmarshalTokenChallenge(data []byte) (TokenChallenge, error) {
	s := cryptobyte.String(data)

	challenge := TokenChallenge{}

	if !s.ReadUint16(&challenge.tokenType) {
		return TokenChallenge{}, fmt.Errorf("Invalid TokenChallenge encoding")
	}

	var issuerName cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&issuerName) || issuerName.Empty() {
		return TokenChallenge{}, fmt.Errorf("Invalid TokenChallenge encoding")
	}
	challenge.issuerName = string(issuerName)

	var redemptionNonce cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&redemptionNonce) {
		return TokenChallenge{}, fmt.Errorf("Invalid TokenChallenge encoding")
	}
	challenge.redemptionNonce = make([]byte, len(redemptionNonce))
	copy(challenge.redemptionNonce, redemptionNonce)

	var originName cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&originName) {
		return TokenChallenge{}, fmt.Errorf("Invalid TokenRequest encoding")
	}
	challenge.originName = string(originName)

	return challenge, nil
}

type TestOrigin struct {
	issuerName       string
	originName       string
	validationKeyEnc []byte // Encoding of validation public key
	validationKey    *rsa.PublicKey
	originNameKey    pat.PublicNameKey

	// Map from challenge hash to list of outstanding challenges
	challenges map[string][]TokenChallenge
}

func (o TestOrigin) CreateChallenge(req *http.Request) string {
	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)
	originName := o.originName

	if req.Header.Get(headerTokenAttributeNoninteractive) != "" {
		// If the client requested a non-interactive token, then clear out the nonce slot
		nonce = []byte{} // empty slice
	}
	if req.Header.Get(headerTokenAttributeCrossOrigin) != "" {
		// If the client requested a cross-origin token, then clear out the origin slot
		originName = ""
	}

	challenge := TokenChallenge{
		tokenType:       uint16(0x0003),
		issuerName:      o.issuerName,
		originName:      originName,
		redemptionNonce: nonce,
	}

	// Add to the running list of challenges
	challengeEnc := challenge.Marshal()
	context := sha256.Sum256(challengeEnc)
	contextEnc := hex.EncodeToString(context[:])
	_, ok := o.challenges[contextEnc]
	if !ok {
		o.challenges[contextEnc] = make([]TokenChallenge, 0)
	}
	o.challenges[contextEnc] = append(o.challenges[contextEnc], challenge)

	return base64.URLEncoding.EncodeToString(challengeEnc)
}

func (o TestOrigin) handleRequest(w http.ResponseWriter, req *http.Request) {
	reqEnc, _ := httputil.DumpRequest(req, false)
	log.Println("Handling request:", string(reqEnc))

	// If the Authorization header is empty, challenge the client for a token
	if req.Header.Get("Authorization") == "" {
		log.Println("Missing authorization header. Replying with challenge.")

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
			challengeString := authorizationAttributeChallenge + "=" + o.CreateChallenge(req)
			issuerKeyString := authorizationAttributeIssuerKey + "=" + base64.URLEncoding.EncodeToString(o.validationKeyEnc)
			maxAgeString := authorizationAttributeMaxAge + "=" + "10"
			originNameKeyString := authorizationAttributeNameKey + "=" + base64.URLEncoding.EncodeToString(o.originNameKey.Marshal())
			challengeList = challengeList + privateTokenType + " " + challengeString + ", " + issuerKeyString + "," + originNameKeyString + ", " + maxAgeString
		}

		w.Header().Set("WWW-Authenticate", challengeList)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	authValue := req.Header.Get("Authorization")
	tokenPrefix := privateTokenType + " " + "token="
	if !strings.HasPrefix(authValue, tokenPrefix) {
		log.Println("Authorization header missing 'PrivateToken token=' prefix")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	tokenValueEnc := strings.SplitAfter(authValue, tokenPrefix)[1] // XXX(caw): there's probably a better way to parse this out
	tokenValue, err := base64.URLEncoding.DecodeString(tokenValueEnc)
	if err != nil {
		log.Println("Failed reading Authorization header token value")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	token, err := pat.UnmarshalToken(tokenValue)
	if err != nil {
		log.Println("Failed decoding Token")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	tokenContextEnc := hex.EncodeToString(token.Context)
	_, ok := o.challenges[tokenContextEnc]
	if !ok {
		log.Println("No outstanding challenge matching context", tokenContextEnc)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	// Consume the challenge
	o.challenges[tokenContextEnc] = o.challenges[tokenContextEnc][1:]
	if len(o.challenges[tokenContextEnc]) == 0 {
		delete(o.challenges, tokenContextEnc)
	}

	authInput := token.AuthenticatorInput()

	hash := sha512.New384()
	hash.Write(authInput)
	digest := hash.Sum(nil)
	err = rsa.VerifyPSS(o.validationKey, crypto.SHA384, digest, token.Authenticator, &rsa.PSSOptions{
		Hash:       crypto.SHA384,
		SaltLength: crypto.SHA384.Size(),
	})
	if err != nil {
		// Token validation failed
		log.Println("Token validation failed", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	httpClient := &http.Client{}
	resourceReq, err := http.NewRequest(http.MethodGet, testResource, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resourceReq.Header.Add("Authorization", "PrivateToken token="+base64.URLEncoding.EncodeToString(token.Marshal()))
	resp, err := httpClient.Do(resourceReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
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
	nameKeyURI, err := composeURL(issuer, issuerConfig.OriginNameKeyURI)
	if err != nil {
		return err
	}
	originNameKey, err := fetchIssuerNameKey(nameKeyURI)
	if err != nil {
		return err
	}

	log.Println("Token verification key:", hex.EncodeToString(publicKeyEnc))

	origin := TestOrigin{
		issuerName:       issuer,
		originName:       name,
		originNameKey:    originNameKey,
		validationKeyEnc: publicKeyEnc,
		validationKey:    publicKey,
		challenges:       make(map[string][]TokenChallenge),
	}

	http.HandleFunc("/", origin.handleRequest)
	err = http.ListenAndServeTLS(":"+port, cert, key, nil)
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
	}
	return err
}
