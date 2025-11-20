package commands

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"

	"github.com/cloudflare/pat-go/tokens"
	"github.com/cloudflare/pat-go/tokens/type2"
)

var (
	ErrNoMatchingToken = errors.New("No matching token")
)

type TokenStore struct {
	store map[string][]tokens.Token
}

func (s *TokenStore) String() string {
	storeEnc, err := s.toJSON()
	if err != nil {
		panic(err)
	}
	return string(storeEnc)
}

func (s *TokenStore) Equals(o *TokenStore) bool {
	for c1, t1 := range s.store {
		t2, ok := o.store[c1]
		if !ok {
			return false
		}
		if len(t1) != len(t2) {
			return false
		}
		for _, v1 := range t1 {
			matching := false
			for _, v2 := range t2 {
				if bytes.Equal(v1.Marshal(), v2.Marshal()) {
					matching = true
				}
			}
			if !matching {
				return false
			}
		}
	}
	for c2, t2 := range o.store {
		t1, ok := o.store[c2]
		if !ok {
			return false
		}
		if len(t1) != len(t2) {
			return false
		}
		for _, v1 := range t1 {
			matching := false
			for _, v2 := range t2 {
				if bytes.Equal(v1.Marshal(), v2.Marshal()) {
					matching = true
				}
			}
			if !matching {
				return false
			}
		}
	}
	return true
}

func (s *TokenStore) AddToken(challenge string, token tokens.Token) {
	_, ok := s.store[challenge]
	if !ok {
		s.store[challenge] = []tokens.Token{}
	}
	s.store[challenge] = append(s.store[challenge], token)
}

func (s *TokenStore) Token(challenge string) (tokens.Token, error) {
	tokenList, ok := s.store[challenge]
	if !ok {
		return tokens.Token{}, ErrNoMatchingToken
	}
	return tokenList[0], nil
}

func (s *TokenStore) ConsumeToken(challenge string) (tokens.Token, error) {
	tokenList, ok := s.store[challenge]
	if !ok {
		return tokens.Token{}, ErrNoMatchingToken
	}
	token := tokenList[0]
	s.store[challenge] = s.store[challenge][1:]
	if len(s.store[challenge]) == 0 {
		delete(s.store, challenge)
	}
	return token, nil
}

func (s *TokenStore) toJSON() ([]byte, error) {
	fileMap := make(map[string][]string)
	for c, l := range s.store {
		fileMap[c] = make([]string, 0)
		for _, t := range l {
			fileMap[c] = append(fileMap[c], hex.EncodeToString(t.Marshal()))
		}
	}
	fileMapEnc, err := json.Marshal(fileMap)
	if err != nil {
		return nil, nil
	}
	return fileMapEnc, nil
}

func (s *TokenStore) WriteToFile(fname string) error {
	fileMapEnc, err := s.toJSON()
	if err != nil {
		return nil
	}

	err = ioutil.WriteFile(fname, fileMapEnc, 0644)
	return err
}

func EmptyStore() *TokenStore {
	return &TokenStore{
		store: make(map[string][]tokens.Token),
	}
}

func ReadStoreFromFile(fname string) (*TokenStore, error) {
	fileMapEnc, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}

	data := make(map[string][]string)
	err = json.Unmarshal(fileMapEnc, &data)
	if err != nil {
		return nil, err
	}

	tokenMap := make(map[string][]tokens.Token)
	for c, l := range data {
		for _, t := range l {
			tokenEnc, err := hex.DecodeString(t)
			if err != nil {
				return nil, err
			}

			token, err := type2.UnmarshalToken(tokenEnc)
			if err != nil {
				return nil, err
			}

			tokenMap[c] = append(tokenMap[c], token)
		}
	}

	return &TokenStore{
		store: tokenMap,
	}, nil
}
