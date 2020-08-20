package alipay

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"net/url"
	"sort"
	"strings"

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

func (this *Client) VerifySign2(data url.Values) (ok bool, err error) {
	var certSN = data.Get(kCertSNNodeName)
	publicKey, err := this.getAliPayPublicKey(certSN)
	if err != nil {
		return false, err
	}

	return verifySign2(data, publicKey)
}

func verifySign2(data url.Values, key *rsa.PublicKey) (ok bool, err error) {
	sign := data.Get(kSignNodeName)

	var keys = make([]string, 0, 0)
	for key := range data {
		if key == kSignNodeName || key == kCertSNNodeName {
			continue
		}
		keys = append(keys, key)
	}

	sort.Strings(keys)

	var pList = make([]string, 0, 0)
	for _, key := range keys {
		pList = append(pList, key+"="+data.Get(key))
	}
	var s = strings.Join(pList, "&")

	return verifyData([]byte(s), sign, key)
}
