package commands

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"testing"

	"crypto/rand"

	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/pat-go"
)

const (
	LINE_WIDTH = 68
)

func chunkStringBySize(input string, chunkLen int) []string {
	inputLen := len(input)
	numChunks := int(math.Ceil(float64(inputLen) / float64(chunkLen)))
	chunks := make([]string, numChunks)
	var start, stop int
	for i := 0; i < numChunks; i += 1 {
		start = i * chunkLen
		stop = start + chunkLen
		if stop > inputLen {
			stop = inputLen
		}
		chunks[i] = input[start:stop]
	}
	return chunks
}

func wrapPrint(input string, width int) {
	for _, chunk := range chunkStringBySize(input, width) {
		fmt.Println(chunk)
	}
}

func TestAuthenticateChallengeHeader(t *testing.T) {
	rsaPrivateKey := loadPrivateKey(t)
	type3TokenKey, err := oprf.GenerateKey(oprf.SuiteP384, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	redemptionNonce := make([]byte, 32)
	_, err = rand.Read(redemptionNonce)
	if err != nil {
		t.Fatal(err)
	}

	type2TokenKeyEnc, err := pat.MarshalTokenKey(&rsaPrivateKey.PublicKey, false)
	if err != nil {
		t.Fatal(err)
	}
	type3TokenKeyEnc, err := type3TokenKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		numChallenges   int
		tokenTypes      []uint16
		tokenKeys       [][]byte
		issuerName      string
		originInfo      []string
		redemptionNonce []byte
		maxAge          int
	}{
		{
			numChallenges:   1,
			tokenTypes:      []uint16{pat.BasicPublicTokenType},
			tokenKeys:       [][]byte{type2TokenKeyEnc},
			issuerName:      "issuer.example",
			originInfo:      []string{"origin.example"},
			redemptionNonce: redemptionNonce,
			maxAge:          10,
		},
		{
			numChallenges:   2,
			tokenTypes:      []uint16{pat.BasicPublicTokenType, pat.BasicPrivateTokenType},
			tokenKeys:       [][]byte{type2TokenKeyEnc, type3TokenKeyEnc},
			issuerName:      "issuer.example",
			originInfo:      []string{"origin.example"},
			redemptionNonce: redemptionNonce,
			maxAge:          10,
		},
	}

	for _, test := range tests {
		var challengeList string
		challenges := make([]pat.TokenChallenge, test.numChallenges)
		for i := 0; i < test.numChallenges; i++ {
			challenges[i] = pat.TokenChallenge{
				TokenType:       test.tokenTypes[i],
				IssuerName:      test.issuerName,
				OriginInfo:      test.originInfo,
				RedemptionNonce: test.redemptionNonce,
			}

			// Add to the running list of challenges
			challengeEnc := challenges[i].Marshal()
			challengeEncBase64 := base64.URLEncoding.EncodeToString(challengeEnc)
			tokenKeyEncBase64 := base64.URLEncoding.EncodeToString(test.tokenKeys[i])

			// challengeEnc, tokenKeyEnc :=
			challengeString := authorizationAttributeChallenge + "=" + "\"" + challengeEncBase64 + "\""
			issuerKeyString := authorizationAttributeTokenKey + "=" + "\"" + tokenKeyEncBase64 + "\""
			maxAgeString := authorizationAttributeMaxAge + "=" + "\"" + strconv.Itoa(test.maxAge) + "\""
			randomKeyString := "unknownChallengeAttribute" + "=" + "\"" + "ignore-me" + "\""
			if i == 0 {
				challengeList = privateTokenType + " " + challengeString + ", " + issuerKeyString + "," + randomKeyString + ", " + maxAgeString
			} else {
				challengeList = challengeList + ", " + privateTokenType + " " + challengeString + ", " + issuerKeyString + "," + randomKeyString + ", " + maxAgeString
			}
		}

		for i := 0; i < test.numChallenges; i++ {
			wrapPrint(fmt.Sprintf("token-type-%d: ", i)+fmt.Sprintf("0x%04x", test.tokenTypes[i]), LINE_WIDTH)
			wrapPrint(fmt.Sprintf("token-key-%d: ", i)+hex.EncodeToString(test.tokenKeys[i]), LINE_WIDTH)
			wrapPrint(fmt.Sprintf("max-age-%d: ", i)+strconv.Itoa(test.maxAge), LINE_WIDTH)
			wrapPrint(fmt.Sprintf("token-challenge-%d: ", i)+hex.EncodeToString(challenges[i].Marshal()), LINE_WIDTH)
		}

		header := "WWW-Authenticate: " + challengeList
		fmt.Println("")
		wrapPrint(header, LINE_WIDTH)
		fmt.Println("")
	}
}
