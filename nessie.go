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

func (n *Nessus) doRequest(method string, resource string, data url.Values, wantStatus []int) (resp *http.Response, err error) {
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

	resp, err = n.client.Do(req)
	if err != nil {
		return nil, err
	}
	var statusFound bool
	for _, status := range wantStatus {
		if resp.StatusCode == status {
			statusFound = true
			break
		}
	}
	if !statusFound {
		return nil, fmt.Errorf("Unexpected status code during login, got %d wanted %s", resp.StatusCode, wantStatus)
	}
	return resp, nil
}

type loginResp struct {
	Token string `json:"token"`
}

// ServerProperties is the structure returned by the ServerProperties() method.
type ServerProperties struct {
	Token           string `json:"token"`
	NessusType      string `json:"nessus_type"`
	NessusUIVersion string `json:"nessus_ui_version"`
	ServerVersion   string `json:"server_version"`
	Feed            string `json:"feed"`
	Enterprise      bool   `json:"enterprise"`
	LoadedPluginSet string `json:"loaded_plugin_set"`
	ServerUUID      string `json:"server_uuid"`
	Expiration      int64  `json:"expiration"`
	Notifications   []struct {
		Type string `json:"type"`
		Msg  string `json:"message"`
	} `json:"notifications"`
	ExpirationTime int64 `json:"expiration_time"`
	Capabilities   struct {
		MultiScanner      bool `json:"multi_scanner"`
		ReportEmailConfig bool `json:"report_email_config"`
	} `json:"capabilities"`
	PluginSet       string `json:"plugin_set"`
	IdleTImeout     int64  `json:"idle_timeout"`
	ScannerBoottime int64  `json:"scanner_boottime"`
	LoginBanner     bool   `json:"login_banner"`
}

// ServerStatus is the stucture returned  by the ServerStatus() method.
type ServerStatus struct {
	Status             string `json:"status"`
	Progress           int64  `json:"progress"`
	MustDestroySession bool
}

// Login will log into nessus with the username and passwords given from the command line flags.
func (n *Nessus) Login(username, password string) error {
	log.Printf("Login into %s\n", n.apiURL)
	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)

	resp, err := n.doRequest("POST", "/session", data, []int{http.StatusOK})
	if err != nil {
		return err
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

	if _, err := n.doRequest("DELETE", "/session", nil, []int{http.StatusOK}); err != nil {
		return err
	}
	n.authCookie = ""
	return nil
}

// ServerProperties will return the current state of the nessus instance.
func (n *Nessus) ServerProperties() (*ServerProperties, error) {
	log.Println("Server properties...")

	resp, err := n.doRequest("GET", "/server/properties", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	reply := &ServerProperties{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// ServerStatus will return the current status of the nessus instance.
func (n *Nessus) ServerStatus() (*ServerStatus, error) {
	log.Println("Server status...")

	resp, err := n.doRequest("GET", "/server/status", nil, []int{http.StatusOK, http.StatusServiceUnavailable})
	if err != nil {
		return nil, err
	}
	reply := &ServerStatus{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		reply.MustDestroySession = true
	}
	return reply, nil
}
