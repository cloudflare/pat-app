package commands

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/cloudflare/pat-go"
	"github.com/urfave/cli"
	"golang.org/x/crypto/hkdf"
)

func fetchIssuerConfig(issuer string) (IssuerConfig, error) {
	resp, err := http.Get("https://" + issuer + issuerConfigURI)
	if err != nil {
		return IssuerConfig{}, err
	}
	defer resp.Body.Close()

	issuerConfigEnc, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return IssuerConfig{}, err
	}

	issuerConfig := IssuerConfig{}
	err = json.Unmarshal(issuerConfigEnc, &issuerConfig)
	if err != nil {
		return IssuerConfig{}, err
	}

	return issuerConfig, nil
}

func fetchIssuerNameKey(nameKeyURI string) (pat.PublicNameKey, error) {
	resp, err := http.Get(nameKeyURI)
	if err != nil {
		return pat.PublicNameKey{}, err
	}
	defer resp.Body.Close()

	nameKeyEnc, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return pat.PublicNameKey{}, err
	}

	nameKey, err := pat.UnmarshalPublicNameKey(nameKeyEnc)
	if err != nil {
		return pat.PublicNameKey{}, err
	}

	return nameKey, nil
}

func fetchOriginTokenKey(tokenKeyURI, origin string) ([]byte, *rsa.PublicKey, error) {
	req, err := http.NewRequest(http.MethodGet, tokenKeyURI, nil)
	if err != nil {
		return nil, nil, err
	}
	q := req.URL.Query()
	if origin != "" {
		q.Add("origin", origin)
	}
	req.URL.RawQuery = q.Encode()

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("Request failed with error %d", resp.StatusCode)
	}

	tokenKeyEnc, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	tokenKey, err := unmarshalTokenKey(tokenKeyEnc)
	if err != nil {
		return nil, nil, err
	}

	return tokenKeyEnc, tokenKey, nil
}

func computeAnonymousOrigin(secret []byte, origin string) ([]byte, error) {
	originID := make([]byte, 32)
	hkdf := hkdf.New(sha256.New, secret, nil, []byte(origin))
	_, err := io.ReadFull(hkdf, originID)
	return originID, err
}

func fetchBasicToken(client pat.BasicPublicClient, attester string, challenge []byte, publicKeyEnc []byte) (pat.Token, error) {
	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)

	tokenKeyID := sha256.Sum256(publicKeyEnc)
	publicKey, err := unmarshalTokenKey(publicKeyEnc)
	if err != nil {
		return pat.Token{}, err
	}

	tokenChallenge, err := UnmarshalTokenChallenge(challenge)
	if err != nil {
		return pat.Token{}, err
	}

	issuerConfig, err := fetchIssuerConfig(tokenChallenge.issuerName)
	if err != nil {
		return pat.Token{}, err
	}

	tokenRequestState, err := client.CreateTokenRequest(challenge, nonce, tokenKeyID[:], publicKey)
	if err != nil {
		return pat.Token{}, err
	}
	tokenRequestEnc := tokenRequestState.Request().Marshal()

	u, err := url.Parse("https://" + tokenChallenge.issuerName + issuerConfig.RequestURI)
	if err != nil {
		return pat.Token{}, err
	}

	tokenRequestURI, err := composeURL(attester, "/token-request")
	if err != nil {
		return pat.Token{}, err
	}

	req, err := http.NewRequest(http.MethodPost, tokenRequestURI, bytes.NewBuffer(tokenRequestEnc))
	if err != nil {
		return pat.Token{}, err
	}
	q := req.URL.Query()
	q.Add("issuer", u.Host)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Content-Type", tokenRequestMediaType)

	reqEnc, _ := httputil.DumpRequest(req, false)
	log.Println("Token request:", string(reqEnc))

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return pat.Token{}, err
	}
	if resp.StatusCode != 200 {
		return pat.Token{}, fmt.Errorf("Request failed with error %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	tokenRespEnc, _ := httputil.DumpResponse(resp, false)
	log.Println("Token response:", string(tokenRespEnc))

	tokenResponse, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return pat.Token{}, err
	}

	return tokenRequestState.FinalizeToken(tokenResponse)
}

func fetchRateLimitedToken(client pat.RateLimitedClient, clientOriginSecret []byte, clientID string, attester string, origin string, challenge []byte, publicKeyEnc []byte) (pat.Token, error) {
	blind := make([]byte, 32)
	rand.Reader.Read(blind)

	nonce := make([]byte, 32)
	rand.Reader.Read(nonce)

	tokenKeyID := sha256.Sum256(publicKeyEnc)
	publicKey, err := unmarshalTokenKey(publicKeyEnc)
	if err != nil {
		return pat.Token{}, err
	}

	tokenChallenge, err := UnmarshalTokenChallenge(challenge)
	if err != nil {
		return pat.Token{}, err
	}

	issuerConfig, err := fetchIssuerConfig(tokenChallenge.issuerName)
	if err != nil {
		return pat.Token{}, err
	}

	issuerNameKeyURI, err := composeURL(tokenChallenge.issuerName, issuerConfig.OriginNameKeyURI)
	if err != nil {
		return pat.Token{}, err
	}
	originNameKey, err := fetchIssuerNameKey(issuerNameKeyURI)
	if err != nil {
		return pat.Token{}, err
	}

	tokenRequestState, err := client.CreateTokenRequest(challenge, nonce, blind, tokenKeyID[:], publicKey, origin, originNameKey)
	if err != nil {
		return pat.Token{}, err
	}
	tokenRequestEnc := tokenRequestState.Request().Marshal()

	anonymousOriginID, err := computeAnonymousOrigin(clientOriginSecret, origin)
	if err != nil {
		return pat.Token{}, err
	}

	u, err := url.Parse("https://" + tokenChallenge.issuerName + issuerConfig.RequestURI)
	if err != nil {
		return pat.Token{}, err
	}

	tokenRequestURI, err := composeURL(attester, "/token-request")
	if err != nil {
		return pat.Token{}, err
	}

	req, err := http.NewRequest(http.MethodPost, tokenRequestURI, bytes.NewBuffer(tokenRequestEnc))
	if err != nil {
		return pat.Token{}, err
	}
	q := req.URL.Query()
	q.Add("issuer", u.Host)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Content-Type", tokenRequestMediaType)

	req.Header.Set(headerTokenOrigin, marshalStructuredBinary(anonymousOriginID))
	req.Header.Set(headerClientOriginKey, marshalStructuredBinary(tokenRequestState.BlindedRequestKey()))
	req.Header.Set(headerRequestBlind, marshalStructuredBinary(blind))
	if clientID != "" {
		req.Header.Set(headerClientID, clientID)
	}

	reqEnc, _ := httputil.DumpRequest(req, false)
	log.Println("Token request:", string(reqEnc))

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return pat.Token{}, err
	}
	if resp.StatusCode != 200 {
		return pat.Token{}, fmt.Errorf("Request failed with error %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	tokenRespEnc, _ := httputil.DumpResponse(resp, false)
	log.Println("Token response:", string(tokenRespEnc))

	tokenResponse, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return pat.Token{}, err
	}

	return tokenRequestState.FinalizeToken(tokenResponse)
}

func runClientFetch(c *cli.Context) error {
	origin := c.String("origin")        // localhost:4567
	resource := c.String("resource")    // "/index.html"
	secret := c.String("secret")        // 32 random bytes
	attester := c.String("attester")    // attester.example:4569
	store := c.String("store")          // token_store.json
	tokenType := c.String("token-type") // "basic" or "rate-limited"
	nonInteractive := c.Bool("non-interactive")
	crossOrigin := c.Bool("cross-origin")
	tokenCount := c.Int("count")
	id := c.String("id")

	if origin == "" {
		log.Fatal("Invalid origin. See README for running instructions.")
	}
	if secret == "" {
		log.Fatal("Invalid client secret. See README for running instructions.")
	}
	if attester == "" {
		log.Fatal("Invalid attester. See README for running instructions.")
	}
	if tokenCount <= 0 || tokenCount > 10 {
		log.Fatal("Invalid token count. See README for running instructions.")
	}

	clientSecret, err := hex.DecodeString(secret)
	if err != nil {
		return err
	}

	clientRequestSecret := make([]byte, 32)
	clientOriginSecret := make([]byte, 32)
	hkdf := hkdf.New(sha256.New, clientSecret, nil, []byte("PAT demo"))
	if _, err := io.ReadFull(hkdf, clientRequestSecret); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(hkdf, clientOriginSecret); err != nil {
		panic(err)
	}

	tokenStore := EmptyStore()
	if store != "" {
		if _, err = os.Stat(store); err == nil {
			log.Println("Reading TokenStore from", store)
			tokenStore, err = ReadStoreFromFile(store)
			if err != nil {
				log.Fatal("Failed reading TokenStore from file ", store, ":", err)
			}
		}
	}

	rateLimitedClient := pat.CreateRateLimitedClientFromSecret(clientRequestSecret)
	basicClient := pat.NewBasicPublicClient()

	resourceURI, err := composeURL(origin, resource)
	if err != nil {
		return err
	}

	httpClient := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, resourceURI, nil)
	if err != nil {
		return err
	}
	if nonInteractive {
		req.Header.Add(headerTokenAttributeNoninteractive, "true")
	}
	if crossOrigin {
		req.Header.Add(headerTokenAttributeCrossOrigin, "true")
	}
	if tokenType == "basic" {
		req.Header.Add(headerTokenType, strconv.Itoa(int(pat.BasicPublicTokenType)))
	}
	if tokenType == "rate-limited" {
		req.Header.Add(headerTokenType, strconv.Itoa(int(pat.RateLimitedTokenType)))
	}
	req.Header.Add(headerTokenAttributeChallengeCount, strconv.Itoa(tokenCount))
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respEnc, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return err
	}
	log.Println(string(respEnc))

	if resp.StatusCode == http.StatusUnauthorized && resp.Header.Get("WWW-Authenticate") != "" {
		authValue := resp.Header.Get("WWW-Authenticate")
		if !strings.HasPrefix(authValue, privateTokenType) {
			return fmt.Errorf("Invalid WWW-Authenticate challenge header")
		}

		var err error
		var challengeBlob []byte
		var tokenKeyEnc []byte

		log.Println("Challenged:", authValue)
		challenges := strings.Split(authValue, privateTokenType)
		tokenChallenges := make([]string, 0)
		for _, challenge := range challenges {
			if len(challenge) > 0 {
				log.Println("Processing PrivateToken challenge:", challenge)
				attributes := strings.Split(challenge, ",")
				for _, attribute := range attributes {
					kv := strings.SplitN(attribute, "=", 2)
					key := strings.TrimSpace(kv[0])
					value := kv[1]

					if key == authorizationAttributeChallenge {
						challengeBlob, err = base64.URLEncoding.DecodeString(value)
						if err != nil {
							return err
						}
					} else if key == authorizationAttributeTokenKey {
						tokenKeyEnc, err = base64.URLEncoding.DecodeString(value)
						if err != nil {
							return err
						}
					} else if key == authorizationAttributeMaxAge {
						// Ignore this attribute for now
					} else {
						log.Println("Unknown key:", key)
					}
				}

				challenge := sha256.Sum256(challengeBlob)
				challengeEnc := hex.EncodeToString(challenge[:])
				tokenChallenges = append(tokenChallenges, challengeEnc)

				tokenType := binary.BigEndian.Uint16(challengeBlob)
				if tokenType == pat.RateLimitedTokenType {
					log.Println("Fetching rate-limited token...")
					token, err := fetchRateLimitedToken(rateLimitedClient, clientOriginSecret, id, attester, origin, challengeBlob, tokenKeyEnc)
					if err != nil {
						return err
					}

					log.Printf("Adding token for challenge %s to the store\n", challengeEnc)
					tokenStore.AddToken(challengeEnc, token)
					log.Println("TokenStore contents:", tokenStore.String())
				} else {
					log.Println("Fetching basic token...")
					token, err := fetchBasicToken(basicClient, attester, challengeBlob, tokenKeyEnc)
					if err != nil {
						return err
					}

					log.Printf("Adding token for challenge %s to the store\n", challengeEnc)
					tokenStore.AddToken(challengeEnc, token)
					log.Println("TokenStore contents:", tokenStore.String())
				}
			}
		}

		// Retry the request with a fresh token using the first matching challenge
		log.Printf("Consuming token for challenge %s from the store\n", tokenChallenges[0])
		token, err := tokenStore.ConsumeToken(tokenChallenges[0])
		if err != nil {
			return err
		}

		req, err := http.NewRequest(http.MethodGet, resourceURI, nil)
		if err != nil {
			return err
		}
		req.Header.Add("Authorization", "PrivateToken token="+base64.URLEncoding.EncodeToString(token.Marshal()))
		resp, err = httpClient.Do(req)
		if err != nil {
			return err
		}

		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		fmt.Println(string(body))

		if store != "" {
			log.Println("Writing TokenStore to", store)
			err = tokenStore.WriteToFile(store)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	return nil
}
