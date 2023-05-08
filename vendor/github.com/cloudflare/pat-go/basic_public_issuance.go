package pat

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"

	"github.com/cloudflare/circl/blindsign"
	"github.com/cloudflare/circl/blindsign/blindrsa"
)

type BasicPublicClient struct {
}

func NewBasicPublicClient() BasicPublicClient {
	return BasicPublicClient{}
}

type BasicPublicTokenRequestState struct {
	tokenInput      []byte
	request         *BasicPublicTokenRequest
	verificationKey *rsa.PublicKey
	verifier        blindsign.VerifierState
}

func (s BasicPublicTokenRequestState) Request() *BasicPublicTokenRequest {
	return s.request
}

func (s BasicPublicTokenRequestState) FinalizeToken(blindSignature []byte) (Token, error) {
	signature, err := s.verifier.Finalize(blindSignature)
	if err != nil {
		return Token{}, err
	}

	tokenData := append(s.tokenInput, signature...)
	token, err := UnmarshalToken(tokenData)
	if err != nil {
		return Token{}, err
	}

	// Sanity check: verify the token signature
	hash := sha512.New384()
	_, err = hash.Write(token.AuthenticatorInput())
	if err != nil {
		return Token{}, err
	}
	digest := hash.Sum(nil)

	err = rsa.VerifyPSS(s.verificationKey, crypto.SHA384, digest, token.Authenticator, &rsa.PSSOptions{
		Hash:       crypto.SHA384,
		SaltLength: crypto.SHA384.Size(),
	})
	if err != nil {
		return Token{}, err
	}

	return token, nil
}

// https://ietf-wg-privacypass.github.io/base-drafts/caw/pp-issuance/draft-ietf-privacypass-protocol.html#name-issuance-protocol-for-publi
func (c BasicPublicClient) CreateTokenRequest(challenge, nonce []byte, tokenKeyID []byte, tokenKey *rsa.PublicKey) (BasicPublicTokenRequestState, error) {
	verifier := blindrsa.NewRSAVerifier(tokenKey, crypto.SHA384)

	context := sha256.Sum256(challenge)
	token := Token{
		TokenType:     BasicPublicTokenType,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         tokenKeyID,
		Authenticator: nil, // No signature computed yet
	}
	tokenInput := token.AuthenticatorInput()

	blindedMessage, verifierState, err := verifier.Blind(rand.Reader, tokenInput)
	if err != nil {
		return BasicPublicTokenRequestState{}, err
	}

	request := &BasicPublicTokenRequest{
		TokenKeyID: tokenKeyID[len(tokenKeyID)-1],
		BlindedReq: blindedMessage,
	}

	requestState := BasicPublicTokenRequestState{
		tokenInput:      tokenInput,
		request:         request,
		verifier:        verifierState,
		verificationKey: tokenKey,
	}

	return requestState, nil
}

func (c BasicPublicClient) CreateTokenRequestWithBlind(challenge, nonce []byte, tokenKeyID []byte, tokenKey *rsa.PublicKey, blind, salt []byte) (BasicPublicTokenRequestState, error) {
	verifier := blindrsa.NewRSAVerifier(tokenKey, crypto.SHA384)

	context := sha256.Sum256(challenge)
	token := Token{
		TokenType:     BasicPublicTokenType,
		Nonce:         nonce,
		Context:       context[:],
		KeyID:         tokenKeyID,
		Authenticator: nil, // No signature computed yet
	}
	tokenInput := token.AuthenticatorInput()
	blindedMessage, verifierState, err := verifier.FixedBlind(tokenInput, blind, salt)
	if err != nil {
		return BasicPublicTokenRequestState{}, err
	}

	request := &BasicPublicTokenRequest{
		TokenKeyID: tokenKeyID[len(tokenKeyID)-1],
		BlindedReq: blindedMessage,
	}

	requestState := BasicPublicTokenRequestState{
		tokenInput:      tokenInput,
		request:         request,
		verifier:        verifierState,
		verificationKey: tokenKey,
	}

	return requestState, nil
}

type BasicPublicIssuer struct {
	tokenKey *rsa.PrivateKey
}

func NewBasicPublicIssuer(key *rsa.PrivateKey) *BasicPublicIssuer {
	return &BasicPublicIssuer{
		tokenKey: key,
	}
}

func (i *BasicPublicIssuer) TokenKey() *rsa.PublicKey {
	return &i.tokenKey.PublicKey
}

func (i *BasicPublicIssuer) TokenKeyID() []byte {
	publicKeyEnc, err := MarshalTokenKeyPSSOID(&i.tokenKey.PublicKey)
	if err != nil {
		panic(err)
	}
	keyID := sha256.Sum256(publicKeyEnc)
	return keyID[:]
}

func (i BasicPublicIssuer) Evaluate(req *BasicPublicTokenRequest) ([]byte, error) {
	signer := blindrsa.NewRSASigner(i.tokenKey)
	blindSignature, err := signer.BlindSign(req.BlindedReq)
	if err != nil {
		return nil, err
	}

	return blindSignature, nil
}
