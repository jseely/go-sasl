package sasl

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func GenerateToken(uri string, duration time.Duration, keyName, key string) (string, error) {
	tokenExpiry := strconv.Itoa(int(time.Now().UTC().Add(duration).Round(time.Second).Unix()))
	sigUri := strings.ToLower(url.QueryEscape(uri))
	h := hmac.New(sha256.New, []byte(key))
	_, err := h.Write([]byte(sigUri + "\n" + tokenExpiry))
	if err != nil {
		return "", err
	}
	sig := url.QueryEscape(base64.StdEncoding.EncodeToString(h.Sum(nil)))
	return fmt.Sprintf("SharedAccessSignature sig=%s&se=%s&skn=%s&sr=%s", sig, tokenExpiry, keyName, sigUri), nil
}
