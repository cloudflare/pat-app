package commands

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	"github.com/cloudflare/pat-go"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"golang.org/x/crypto/hkdf"
)

func visit(rateLimitedClient pat.RateLimitedClient, basicClient pat.BasicPublicClient, id string, clientOriginSecret []byte, origin, attester, resourceURI string, nonInteractive, crossOrigin bool, tokenType uint16, tokenCount int) error {
	tokenStore := EmptyStore()

	req, err := http.NewRequest(http.MethodGet, resourceURI, nil)
	if err != nil {
		return err
	}
	if nonInteractive {
		req.URL.Query().Add("noninteractive", "1")
	}
	if crossOrigin {
		req.URL.Query().Add("crossorigin", "1")
	}
	req.URL.Query().Add("type", strconv.Itoa(int(tokenType)))
	req.URL.Query().Add("count", strconv.Itoa(int(tokenCount)))

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respEnc, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return err
	}
	log.Debugln(string(respEnc))

	if resp.StatusCode == http.StatusUnauthorized && resp.Header.Get("WWW-Authenticate") != "" {
		authValue := resp.Header.Get("WWW-Authenticate")
		if !strings.HasPrefix(authValue, privateTokenType) {
			return fmt.Errorf("Invalid WWW-Authenticate challenge header")
		}

		var err error
		var challengeBlob []byte
		var tokenKeyEnc []byte

		log.Debugln("Challenged:", authValue)
		challenges := strings.Split(authValue, privateTokenType)
		tokenChallenges := make([]string, 0)
		for _, challenge := range challenges {
			if len(challenge) > 0 {
				log.Debugln("Processing PrivateToken challenge:", challenge)
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
						log.Debugln("Unknown key:", key)
					}
				}

				challenge := sha256.Sum256(challengeBlob)
				challengeEnc := hex.EncodeToString(challenge[:])
				tokenChallenges = append(tokenChallenges, challengeEnc)

				tokenType := binary.BigEndian.Uint16(challengeBlob)
				if tokenType == pat.RateLimitedTokenType {
					log.Debugln("Fetching rate-limited token...")
					token, err := fetchRateLimitedToken(rateLimitedClient, clientOriginSecret, id, attester, origin, challengeBlob, tokenKeyEnc)
					if err != nil {
						return err
					}

					log.Debugf("Adding token for challenge %s to the store\n", challengeEnc)
					tokenStore.AddToken(challengeEnc, token)
					log.Debugln("TokenStore contents:", tokenStore.String())
				} else {
					// log.Println("Fetching basic token...")
					token, err := fetchBasicToken(basicClient, attester, challengeBlob, tokenKeyEnc)
					if err != nil {
						return err
					}

					log.Debugf("Adding token for challenge %s to the store\n", challengeEnc)
					tokenStore.AddToken(challengeEnc, token)
					log.Debugln("TokenStore contents:", tokenStore.String())
				}
			}
		}

		// Retry the request with a fresh token using the first matching challenge
		log.Debugf("Consuming token for challenge %s from the store\n", tokenChallenges[0])
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
	}
	return nil
}

func runRunner(c *cli.Context) error {
	origin := c.String("origin")     // localhost:4567
	secret := c.String("secret")     // 32 random bytes
	resource := c.String("resource") // "/index.html"
	attester := c.String("attester") // attester.example:4569
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

	rateLimitedClient := pat.NewRateLimitedClientFromSecret(clientRequestSecret)
	basicClient := pat.NewBasicPublicClient()
	resourceURI, err := composeURL(origin, resource)
	if err != nil {
		return err
	}

	var variants = []struct {
		tokenType      uint16
		nonInteractive bool
		crossOrigin    bool
		tokenCount     int
	}{
		{
			tokenType:      pat.BasicPublicTokenType,
			nonInteractive: true,
			crossOrigin:    true,
			tokenCount:     1,
		},
		{
			tokenType:      pat.BasicPublicTokenType,
			nonInteractive: false,
			crossOrigin:    true,
			tokenCount:     1,
		},
		{
			tokenType:      pat.BasicPublicTokenType,
			nonInteractive: true,
			crossOrigin:    false,
			tokenCount:     1,
		},
		{
			tokenType:      pat.BasicPublicTokenType,
			nonInteractive: false,
			crossOrigin:    false,
			tokenCount:     1,
		},
		{
			tokenType:      pat.RateLimitedTokenType,
			nonInteractive: true,
			crossOrigin:    true,
			tokenCount:     1,
		},
		{
			tokenType:      pat.RateLimitedTokenType,
			nonInteractive: false,
			crossOrigin:    true,
			tokenCount:     1,
		},
		{
			tokenType:      pat.RateLimitedTokenType,
			nonInteractive: true,
			crossOrigin:    false,
			tokenCount:     1,
		},
		{
			tokenType:      pat.RateLimitedTokenType,
			nonInteractive: false,
			crossOrigin:    false,
			tokenCount:     1,
		},
	}

	for _, variant := range variants {
		err := visit(rateLimitedClient, basicClient, id, clientOriginSecret, origin, attester, resourceURI, variant.nonInteractive, variant.crossOrigin, variant.tokenType, variant.tokenCount)
		if err != nil {
			log.Printf("Variant [type=0x%04x, non-interactive=%t, cross-origin=%t] failed: %s\n", variant.tokenType, variant.nonInteractive, variant.crossOrigin, err.Error())
		} else {
			log.Printf("Variant [type=0x%04x, non-interactive=%t, cross-origin=%t] succeeded\n", variant.tokenType, variant.nonInteractive, variant.crossOrigin)
		}
	}

	return nil
}
