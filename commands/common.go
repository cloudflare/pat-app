package commands

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
)

var (
	ErrInvalidBinaryHeader = errors.New("Invalid sf-binary header")
)

func handleHTTPError(w http.ResponseWriter, err error, statusCode int) {
	log.Println(err.Error())
	http.Error(w, err.Error(), statusCode)
}

func composeURL(host, uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}

	if u.IsAbs() {
		return uri, nil
	} else {
		result := "https://" + host + u.Path
		if u.RawQuery != "" {
			result = result + "?" + u.RawQuery
		}
		return result, nil
	}
}

func marshalStructuredBinary(data []byte) string {
	return ":" + base64.StdEncoding.EncodeToString(data) + ":"
}

func unmarshalStructuredBinary(data string) ([]byte, error) {
	if strings.Index(data, ":") != 0 {
		return nil, ErrInvalidBinaryHeader
	}
	if strings.LastIndex(data, ":") != (len(data) - 1) {
		return nil, ErrInvalidBinaryHeader
	}
	return base64.StdEncoding.DecodeString(data[1 : len(data)-1])
}
