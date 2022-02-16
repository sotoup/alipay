package alipay

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

func (this *Client) UploadImage(filename string, fp string, result interface{}) error {

	file, err := os.Open(fp)
	if err != nil {
		return err
	}
	defer file.Close()

	resType := strings.TrimLeft(filepath.Ext(fp), ".")

	apiName := "alipay.offline.material.image.upload"
	var p = url.Values{}
	p.Add("app_id", this.appId)
	p.Add("method", apiName)
	p.Add("format", kFormat)
	p.Add("charset", kCharset)
	p.Add("sign_type", kSignTypeRSA2)
	p.Add("timestamp", time.Now().In(this.location).Format(kTimeFormat))
	p.Add("version", kVersion)
	p.Add("image_type", resType)
	p.Add("image_name", filename)

	psign, err := signWithPKCS1v15(p, this.appPrivateKey, crypto.SHA256)
	if err != nil {
		return err
	}
	p.Add("sign", psign)

	apiURL := this.apiDomain + "?" + p.Encode()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("image_type", resType)
	writer.WriteField("image_name", filename)

	part, err := writer.CreateFormFile("image_content", filename)
	if err != nil {
		return err
	}
	_, err = io.Copy(part, file)
	err = writer.Close()
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", apiURL, body)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", writer.FormDataContentType())

	resp, err := this.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var dataStr = string(data)

	var rootNodeName = strings.Replace(apiName, ".", "_", -1) + kResponseSuffix

	var rootIndex = strings.LastIndex(dataStr, rootNodeName)
	var errorIndex = strings.LastIndex(dataStr, kErrorResponse)

	var content string
	var certSN string
	var sign string

	if rootIndex > 0 {
		content, certSN, sign = parseJSONSource(dataStr, rootNodeName, rootIndex)
		if sign == "" {
			var errRsp *ErrorRsp
			if err = json.Unmarshal([]byte(content), &errRsp); err != nil {
				return err
			}

			// alipay.open.app.alipaycert.download(应用支付宝公钥证书下载) 没有返回 sign 字段，所以再判断一次 code
			if errRsp.Code != CodeSuccess {
				if errRsp != nil {
					return errRsp
				}
				return ErrSignNotFound
			}
		}
	} else if errorIndex > 0 {
		content, certSN, sign = parseJSONSource(dataStr, kErrorResponse, errorIndex)
		if sign == "" {
			var errRsp *ErrorRsp
			if err = json.Unmarshal([]byte(content), &errRsp); err != nil {
				return err
			}
			return errRsp
		}
	} else {
		return ErrSignNotFound
	}

	if sign != "" {
		publicKey, err := this.getAliPayPublicKey(certSN)
		if err != nil {
			return err
		}

		if ok, err := verifyData([]byte(content), sign, publicKey); ok == false {
			return err
		}
	}

	err = json.Unmarshal(data, result)
	if err != nil {
		return err
	}

	return err
}

type FormDataParam interface {
	APIName() string
	Params() map[string]string
	FormData() map[string]string
	FormFile() map[string]string
}

// DoRequestWithFormData -
func (this *Client) DoRequestWithFormData(param FormDataParam, result interface{}) error {

	apiName := param.APIName()
	var p = url.Values{}
	p.Add("app_id", this.appId)
	p.Add("method", apiName)
	p.Add("format", kFormat)
	p.Add("charset", kCharset)
	p.Add("sign_type", kSignTypeRSA2)
	p.Add("timestamp", time.Now().In(this.location).Format(kTimeFormat))
	p.Add("version", kVersion)
	if this.appCertSN != "" {
		p.Add("app_cert_sn", this.appCertSN)
	}
	if this.rootCertSN != "" {
		p.Add("alipay_root_cert_sn", this.rootCertSN)
	}

	var ps = param.Params()
	for key, value := range ps {
		if key == kAppAuthToken && value == "" {
			continue
		}
		p.Add(key, value)
	}

	formValues := param.FormData()
	for k, v := range formValues {
		p.Add(k, v)
	}

	psign, err := signWithPKCS1v15(p, this.appPrivateKey, crypto.SHA256)
	if err != nil {
		return err
	}
	p.Add("sign", psign)

	apiURL := this.apiDomain + "?" + p.Encode()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	for k, v := range formValues {
		writer.WriteField(k, v)
	}

	formFiles := param.FormFile()
	for k, v := range formFiles {
		if st, err := os.Stat(v); err != nil || st.IsDir() {
			return fmt.Errorf("file %s not found", v)
		}

		part, err := writer.CreateFormFile(k, filepath.Base(v))
		if err != nil {
			return err
		}

		file, err := os.Open(v)
		if err != nil {
			return err
		}
		io.Copy(part, file)
		file.Close()
	}

	err = writer.Close()
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", apiURL, body)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", writer.FormDataContentType())

	resp, err := this.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var dataStr = string(data)

	var rootNodeName = strings.Replace(apiName, ".", "_", -1) + kResponseSuffix

	var rootIndex = strings.LastIndex(dataStr, rootNodeName)
	var errorIndex = strings.LastIndex(dataStr, kErrorResponse)

	var content string
	var certSN string
	var sign string

	if rootIndex > 0 {
		content, certSN, sign = parseJSONSource(dataStr, rootNodeName, rootIndex)
		if sign == "" {
			var errRsp *ErrorRsp
			if err = json.Unmarshal([]byte(content), &errRsp); err != nil {
				return err
			}

			// alipay.open.app.alipaycert.download(应用支付宝公钥证书下载) 没有返回 sign 字段，所以再判断一次 code
			if errRsp.Code != CodeSuccess {
				if errRsp != nil {
					return errRsp
				}
				return ErrSignNotFound
			}
		}
	} else if errorIndex > 0 {
		content, certSN, sign = parseJSONSource(dataStr, kErrorResponse, errorIndex)
		if sign == "" {
			var errRsp *ErrorRsp
			if err = json.Unmarshal([]byte(content), &errRsp); err != nil {
				return err
			}
			return errRsp
		}
	} else {
		return ErrSignNotFound
	}

	if sign != "" {
		publicKey, err := this.getAliPayPublicKey(certSN)
		if err != nil {
			return err
		}

		if ok, err := verifyData([]byte(content), sign, publicKey); !ok {
			return err
		}
	}

	err = json.Unmarshal(data, result)
	if err != nil {
		return err
	}

	return err
}
