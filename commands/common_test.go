package commands

import (
	"bytes"
	"strings"
	"testing"
)

func TestBinaryHeaderMarshal(t *testing.T) {
	data := []byte{0, 1, 2, 3}
	headerVal := marshalStructuredBinary(data)
	if strings.Index(headerVal, ":") != 0 {
		t.Fatal("Invalid binary header")
	}
	if strings.LastIndex(headerVal, ":") != len(headerVal)-1 {
		t.Fatal("Invalid binary header")
	}
	recoveredData, err := unmarshalStructuredBinary(headerVal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, recoveredData) {
		t.Fatal("Data mismatch")
	}
}
