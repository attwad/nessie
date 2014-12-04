package nessie

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

// Nessus implements most of the communication with Nessus.
type Nessus struct {
	// client is the HTTP client to use to issue requests to nessus.
	client *http.Client
	// authCookie is the login token returned by nessus upon successful login.
	authCookie string
	apiURL     string
}

// NewNessus will return a new Nessus initialized with a client matching the security parameters.
// if caCertPath is empty, the host certificate roots will be used to check for the validity of the nessus server API certificate.
func NewNessus(apiURL, caCertPath string, ignoreSSLCertsErrors bool) (*Nessus, error) {
	var roots *x509.CertPool
	if len(caCertPath) != 0 {
		roots = x509.NewCertPool()
		rootPEM, err := ioutil.ReadFile(caCertPath)
		if err != nil {
			return nil, err
		}
		ok := roots.AppendCertsFromPEM(rootPEM)
		if !ok {
			return nil, fmt.Errorf("could not append certs from PEM %s", caCertPath)
		}
	}
	return &Nessus{
		apiURL: apiURL,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: ignoreSSLCertsErrors,
					RootCAs:            roots,
				},
			},
		},
	}, nil
}

func (n *Nessus) doRequest(method string, resource string, data url.Values) (resp *http.Response, err error) {
	u, err := url.ParseRequestURI(n.apiURL)
	if err != nil {
		return nil, err
	}
	u.Path = resource
	urlStr := fmt.Sprintf("%v", u)

	req, err := http.NewRequest(method, urlStr, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
	req.Header.Add("Accept", "application/json")
	if n.authCookie != "" {
		req.Header.Add("X-Cookie", fmt.Sprintf("token=%s", n.authCookie))
	}

	return n.client.Do(req)
}

type loginResp struct {
	Token string `json:"token"`
}

// Login will log into nessus with the username and passwords given from the command line flags.
func (n *Nessus) Login(username, password string) error {
	log.Printf("Login into %s\n", n.apiURL)
	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)

	resp, err := n.doRequest("POST", "/session", data)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Unexpected status code during login: %d", resp.StatusCode)
	}
	reply := &loginResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return err
	}
	n.authCookie = reply.Token
	return nil
}

// Logout will invalidate the current session token.
func (n *Nessus) Logout() error {
	if n.authCookie == "" {
		log.Println("Not logged in, nothing to do to logout...")
		return nil
	}
	log.Println("Logout...")

	resp, err := n.doRequest("DELETE", "/session", nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Unexpected status code during logout: %d", resp.StatusCode)
	}
	n.authCookie = ""
	return nil
}
