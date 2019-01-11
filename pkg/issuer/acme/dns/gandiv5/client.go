package gandiv5

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/golang/glog"
	pkgutil "github.com/jetstack/cert-manager/pkg/util"
)

// types for JSON responses with only a message
type apiResponse struct {
	Message string `json:"message"`
	UUID    string `json:"uuid,omitempty"`
}

// Record TXT record representation
type Record struct {
	RRSetTTL    int      `json:"rrset_ttl"`
	RRSetValues []string `json:"rrset_values"`
	RRSetName   string   `json:"rrset_name,omitempty"`
	RRSetType   string   `json:"rrset_type,omitempty"`
}

func (d *DNSProvider) setRecord(domain, rtype, name, value string, ttl int) error {
	target := fmt.Sprintf("domains/%s/records/%s/%s", domain, name, rtype)
	newRecord := &Record{RRSetTTL: ttl, RRSetValues: []string{value}}
	req, err := d.newRequest(http.MethodPut, target, newRecord)
	if err != nil {
		return err
	}

	message := &apiResponse{}
	err = d.do(req, message)
	if err != nil {
		return fmt.Errorf("unable to create %s record for domain %s and name %s: %v", rtype, domain, name, err)
	}

	if message != nil && len(message.Message) > 0 {
		glog.Infof("API response: %s", message.Message)
	}

	return nil
}

func (d *DNSProvider) getRecord(domain, rtype, name string) (*Record, error) {
	target := fmt.Sprintf("domains/%s/records/%s/%s", domain, name, rtype)

	// Get exiting values for the TXT records
	// Needed to create challenges for both wildcard and base name domains
	req, err := d.newRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}

	record := &Record{}
	err = d.do(req, record)
	if err != nil {
		return nil, fmt.Errorf("unable to get %s records for domain %s and name %s: %v", rtype, domain, name, err)
	}

	return record, nil
}

func (d *DNSProvider) deleteRecord(domain, rtype, name string) error {
	target := fmt.Sprintf("domains/%s/records/%s/%s", domain, name, rtype)

	req, err := d.newRequest(http.MethodDelete, target, nil)
	if err != nil {
		return err
	}

	message := &apiResponse{}
	err = d.do(req, message)
	if err != nil {
		return fmt.Errorf("unable to delete %s record for domain %s and name %s: %v", rtype, domain, name, err)
	}

	if message != nil && len(message.Message) > 0 {
		glog.Infof("API response: %s", message.Message)
	}

	return nil
}

func (d *DNSProvider) newRequest(method, resource string, body interface{}) (*http.Request, error) {
	var req *http.Request
	var err error
	u := fmt.Sprintf("%s/%s", d.APIUrl, resource)

	if body == nil {
		req, err = http.NewRequest(method, u, nil)
	} else {
		reqBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		req, err = http.NewRequest(method, u, bytes.NewBuffer(reqBody))
	}

	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", d.APIKey)
	req.Header.Set("User-Agent", pkgutil.CertManagerUserAgent)

	return req, nil
}

func (d *DNSProvider) do(req *http.Request, v interface{}) error {
	client := http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	err = checkResponse(resp)
	if err != nil {
		return err
	}

	if v == nil {
		return nil
	}

	raw, err := readBody(resp)
	if err != nil {
		return fmt.Errorf("failed to read body: %v", err)
	}

	if len(raw) > 0 {
		err = json.Unmarshal(raw, v)
		if err != nil {
			return fmt.Errorf("unmarshaling error: %v: %s", err, string(raw))
		}
	}

	return nil
}

func checkResponse(resp *http.Response) error {
	if resp.StatusCode == 404 && resp.Request.Method == http.MethodGet {
		return nil
	}

	if resp.StatusCode >= 400 {
		data, err := readBody(resp)
		if err != nil {
			return fmt.Errorf("%d [%s] request failed: %v", resp.StatusCode, http.StatusText(resp.StatusCode), err)
		}

		message := &apiResponse{}
		err = json.Unmarshal(data, message)
		if err != nil {
			return fmt.Errorf("%d [%s] request failed: %v: %s", resp.StatusCode, http.StatusText(resp.StatusCode), err, data)
		}
		return fmt.Errorf("%d [%s] request failed: %s", resp.StatusCode, http.StatusText(resp.StatusCode), message.Message)
	}

	return nil
}

func readBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, fmt.Errorf("response body is nil")
	}

	defer resp.Body.Close()

	rawBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return rawBody, nil
}
