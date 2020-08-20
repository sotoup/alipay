package alipay

import (
	"crypto"
	"encoding/base64"

	"github.com/smartwalle/crypto4go"
)

func (this *Client) SignString(s string) (string, error) {
	sig, err := crypto4go.RSASignWithKey([]byte(s), this.appPrivateKey, crypto.SHA256)
	if err != nil {
		return "", err
	}
	s = base64.StdEncoding.EncodeToString(sig)
	return s, nil
}
