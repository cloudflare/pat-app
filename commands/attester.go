package commands

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"strconv"

	pat "github.com/cloudflare/pat-go"
	"github.com/urfave/cli"
)

var (
	// Token request URL
	attesterTokenRequestURI = "/token-request"

	// Headers exchanged during the issuance protocol
	headerTokenOrigin     = "sec-token-origin"
	headerClientOriginKey = "sec-token-client"
	headerRequestBlind    = "sec-token-request-blind"
	headerClientID        = "sec-client-id"
	headerTokenLimit      = "sec-token-limit"

	// Rate-limited issuance protocol type
	patTokenType = uint16(0x0003)
)

type ClientState struct {
	// XXX(caw): this needs to include a timestamp to allow for rotation
	originIndices map[string]string // map from anonymous origin ID to stable index
	originCounts  map[string]int    // map from anonymous origin ID to per-origin count
}

type TestAttester struct {
	client      *http.Client
	clientState map[string]ClientState
}

func parseStructuredBinaryHeader(req *http.Request, header string) ([]byte, error) {
	if req.Header.Get(header) == "" {
		log.Println("Header", header, "missing")
		return nil, fmt.Errorf("Header %s missing", header)
	}
	return unmarshalStructuredBinary(req.Header.Get(header))
}

func (a TestAttester) handleAttestationRequest(w http.ResponseWriter, req *http.Request) {
	reqEnc, _ := httputil.DumpRequest(req, false)
	log.Println("Handling attestation token request:", string(reqEnc))

	// Sanity check the request format
	if req.Method != http.MethodPost {
		log.Println("Invalid method")
		http.Error(w, "Invalid method", 400)
		return
	}
	if req.Header.Get("Content-Type") != tokenRequestMediaType {
		log.Println("Invalid content type")
		http.Error(w, "Invalid Content-Type", 400)
		return
	}

	// Parse sf-binary headers
	anonOrigin, err := parseStructuredBinaryHeader(req, headerTokenOrigin)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), 400)
		return
	}
	clientOriginKey, err := parseStructuredBinaryHeader(req, headerClientOriginKey)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), 400)
		return
	}
	requestBlind, err := parseStructuredBinaryHeader(req, headerRequestBlind)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), 400)
		return
	}
	var clientID string
	clientID = req.Header.Get(headerClientID)
	if clientID == "" {
		clientID = "default"
	}

	// Read the target issuer
	targetName := req.URL.Query().Get("issuerhost")
	if targetName == "" {
		log.Println("Issuer host missing")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Read the client's token request from the body and check the token type
	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Println("Failed reading client request body:", err)
		http.Error(w, err.Error(), 400)
		return
	}

	clientTokenReq, err := pat.UnmarshalTokenRequest(requestBody)
	if err != nil {
		log.Println("Failed parsing client TokenRequest", err)
		http.Error(w, err.Error(), 400)
		return
	}

	if clientTokenReq.Type() != patTokenType {
		log.Println("Unsupported token request type")
		http.Error(w, "Unsupported token request type", 400)
		return
	}

	targetURI, err := composeURL(targetName, tokenRequestURI)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	log.Println("Target:", targetURI)

	// XXX(caw): get the policy information from the issuer's .well-known: /.well-known/token-issuer-directory
	// https://tfpauly.github.io/privacy-proxy/draft-privacypass-rate-limit-tokens.html#name-configuration

	tokenReq, err := http.NewRequest(http.MethodPost, targetURI, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Println("Failed creating forwarding request:", err)
		http.Error(w, err.Error(), 400)
		return
	}
	tokenReq.Header.Set("Content-Type", tokenRequestMediaType)

	tokenReqEnc, _ := httputil.DumpRequest(tokenReq, false)
	log.Println("Forwarding attestation token request:", string(tokenReqEnc))

	resp, err := a.client.Do(tokenReq)
	if err != nil {
		log.Println("Forwarded request failed:", err)
		http.Error(w, err.Error(), 400)
		return
	}
	defer resp.Body.Close()

	if resp.Header.Get(headerTokenLimit) == "" {
		log.Println("Response missing " + headerTokenLimit + " header")
		http.Error(w, "Response missing "+headerTokenLimit+" header", 400) // XXX(caw): fix this response code
		return
	}
	tokenLimit, err := strconv.Atoi(resp.Header.Get(headerTokenLimit))
	if err != nil {
		log.Println("Invalid " + headerTokenLimit + " header")
		http.Error(w, "Invalid "+headerTokenLimit+" header", 400) // XXX(caw): fix this response code
		return
	}

	tokenRespEnc, _ := httputil.DumpResponse(resp, false)
	log.Println("Attestation token response:", string(tokenRespEnc))

	blindSignature, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	blindedRequestKey, err := unmarshalStructuredBinary(resp.Header.Get(headerTokenOrigin))
	if err != nil {
		log.Println("Invalid "+headerTokenOrigin+" header:", err)
		http.Error(w, "Invalid "+headerTokenOrigin+" header", 400)
		return
	}

	index, err := pat.FinalizeIndex(clientOriginKey, requestBlind, blindedRequestKey)
	if err != nil {
		log.Println("Index computation failed:", err)
		http.Error(w, "Index computation failed", 400)
		return
	}
	indexEnc := hex.EncodeToString(index)

	anonOriginEnc := hex.EncodeToString(anonOrigin)
	state, ok := a.clientState[clientID]
	if !ok {
		log.Println("Initializing new state for client", clientID)

		// No client state for this client, so initialize it
		originIndices := make(map[string]string)
		originIndices[anonOriginEnc] = indexEnc
		originCounts := make(map[string]int)
		originCounts[anonOriginEnc] = 1
		a.clientState[clientID] = ClientState{
			originIndices: originIndices,
			originCounts:  originCounts,
		}
	} else {
		log.Println("Updating state for client", clientID)
		oldIndexEnc, ok := state.originIndices[anonOriginEnc]
		if !ok {
			log.Println("Recording new origin for client", clientID)

			// This is a newly visited origin, so initialize it as such
			state.originIndices[anonOriginEnc] = indexEnc
			state.originCounts[anonOriginEnc] = 1
		} else {
			log.Println("Updating existing origin for client", clientID)

			// Check for index stability
			if oldIndexEnc != indexEnc {
				if err != nil {
					log.Println("Index mismatch for client", clientID)
					http.Error(w, "Invalid mapping, aborting", 400)
					return
				}
			} else {
				log.Println("Incrementing index count for client", clientID)
				state.originCounts[indexEnc] = state.originCounts[indexEnc] + 1

				if state.originCounts[indexEnc] >= tokenLimit {
					log.Println("Limit", tokenLimit, "exceeded")
					http.Error(w, "Limit exceeded", http.StatusTooManyRequests)
					return
				}
			}
		}
	}

	w.Header().Set("content-type", tokenResponseMediaType)
	w.Write(blindSignature)
}

func startAttester(c *cli.Context) error {
	cert := c.String("cert")
	key := c.String("key")
	port := c.String("port")

	if cert == "" {
		log.Fatal("Invalid key material (missing certificate). See README for configuration.")
	}
	if key == "" {
		log.Fatal("Invalid key material (missing private key). See README for configuration.")
	}

	attester := TestAttester{
		client:      &http.Client{},
		clientState: make(map[string]ClientState),
	}

	http.HandleFunc(attesterTokenRequestURI, attester.handleAttestationRequest)
	err := http.ListenAndServeTLS(":"+port, cert, key, nil)
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
	}
	return err
}
