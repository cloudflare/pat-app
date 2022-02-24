package commands

import (
	"encoding/base64"
	"encoding/hex"
	"log"
	"testing"
)

// XXX(caw): improveme
func createTokenChallenge() TokenChallenge {
	// return pat.Token{
	// 	TokenType:     0x0003,
	// 	Nonce:         make([]byte, 32),
	// 	Context:       make([]byte, 32),
	// 	KeyID:         make([]byte, 32),
	// 	Authenticator: make([]byte, 512),
	// }
	return TokenChallenge{}
}

func TestTokenChallengeUnmarshal(t *testing.T) {
	testChallenge := "AAIAImlzc3Vlci5wYXQucmVzZWFyY2guY2xvdWRmbGFyZS5jb20AAAAA"
	challengeBlob, err := base64.URLEncoding.DecodeString(testChallenge)
	if err != nil {
		t.Fatal(err)
	}

	log.Print(hex.EncodeToString(challengeBlob))

	challenge, err := UnmarshalTokenChallenge(challengeBlob)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(challenge)
}

func TestBase64(t *testing.T) {
	v := "MIICUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAg8AMIICCgKCAgEAqf6VmRe_ws8ZWvoxAZ847LQpleN6I0daqdxBY61GVim4bRv9g6xAxaZWcKpu58TbWpDVU6sQw7l58W-C1jmJvobGqtZF4WHqtvqdQZdSbkxbpcgwVJsGuwyJjMNs7koEUfB50Tb2XgdmnuFS0gAxRxVIZghxPkfjgBnT0cQpNDxLf-uO9C-NnoonU4rhoPhiA1IdlApOk2mJuks335nfT4fyAcPbMOsd__XL0dSs_T5s4lxkuKo12p0mURg_Zs1OEucgGxDpVrRA-kZ6iFQKIJNZ_fZ396Yok8jAvRyhEBJbqyhApFG9d3v2-3CmGUuJgyzcb2lI0y86EuCf9A_DR2FK2aV0_fxfRiXji1WER-LTUsM-SqwYYhouFFXIHrXUsI4H5RiDE_4EEAqh4duhaenTne7SDl8Talr2IK-gXFffdkI6g6X2xDg159xT-LeSWE0tk_lFAJkS3GhqZVfB7ikZtpxsJs2pIf26XpRPBydhQgTY2rKx9KuMJoQStolRNAv7b_Z8CfrJj6ZMWaodntmZ0TZ6p6mIq5kKpgsx8kDf125Bwxv0XL-sDO2vhWzCvK6dLWefxrm8aj_F5tz0aL8asgLCr9aFtNbQl96TzcEJcYGCq5BbsqeoIBt2W6nfr3LDHb22zmiiyaH6Pb5eTfDjWTSPEfJ8mjQOZsiD1GsCAwEAAQ"
	_, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		t.Fatal(err)
	}
}
