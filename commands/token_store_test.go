package commands

import (
	"os"
	"testing"

	"github.com/cloudflare/pat-go"
)

func createEmptyToken() pat.Token {
	return pat.Token{
		TokenType:     0x0003,
		Nonce:         make([]byte, 32),
		Context:       make([]byte, 32),
		KeyID:         make([]byte, 32),
		Authenticator: make([]byte, 512),
	}
}

func TestLoadStore(t *testing.T) {
	store := EmptyStore()
	store.AddToken("test1", createEmptyToken())
	store.AddToken("test2", createEmptyToken())

	fname := "_test_store.json"
	err := store.WriteToFile(fname)
	if err != nil {
		t.Fatal(err)
	}

	newStore, err := ReadStoreFromFile(fname)
	if err != nil {
		t.Fatal(err)
	}

	if !store.Equals(newStore) {
		t.Fatal("token store mismatch")
	}

	err = os.Remove(fname)
	if err != nil {
		t.Fatal(err)
	}
}
