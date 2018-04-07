package sasl

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

func GenerateToken(uri string, duration time.Duration, keyName string, key []byte) (string, error) {
	tokenExpiry := strconv.Itoa(int(time.Now().UTC().Add(duration).Round(time.Second).Unix()))
	sigUri := url.QueryEscape(uri)
	h := hmac.New(sha256.New, key)
	_, err := h.Write([]byte(sigUri + "\n" + tokenExpiry))
	if err != nil {
		return "", err
	}
	sig := url.QueryEscape(base64.StdEncoding.EncodeToString(h.Sum(nil)))
	return fmt.Sprintf("SharedAccessSignature sr=%s&sig=%s&se=%s", sigUri, sig, tokenExpiry), nil
}
