package nessie

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
)

var debug bool

func init() {
	flag.BoolVar(&debug, "debug", false, "log the responses from nessus")
}

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

func (n *Nessus) doRequest(method string, resource string, js interface{}, wantStatus []int) (resp *http.Response, err error) {
	u, err := url.ParseRequestURI(n.apiURL)
	if err != nil {
		return nil, err
	}
	u.Path = resource
	urlStr := fmt.Sprintf("%v", u)

	jb, err := json.Marshal(js)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, urlStr, bytes.NewBufferString(string(jb)))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	if n.authCookie != "" {
		req.Header.Add("X-Cookie", fmt.Sprintf("token=%s", n.authCookie))
	}

	if debug {
		db, err := httputil.DumpRequest(req, true)
		if err != nil {
			return nil, err
		}
		log.Println("sending data:", string(db))
	}
	resp, err = n.client.Do(req)
	if err != nil {
		return nil, err
	}
	if debug {
		if body, err := httputil.DumpResponse(resp, true); err == nil {
			log.Println(string(body))
		}
	}
	var statusFound bool
	for _, status := range wantStatus {
		if resp.StatusCode == status {
			statusFound = true
			break
		}
	}
	if !statusFound {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("Unexpected status code, got %d wanted %v (%s)", resp.StatusCode, wantStatus, body)
	}
	return resp, nil
}

// Login will log into nessus with the username and passwords given from the command line flags.
func (n *Nessus) Login(username, password string) error {
	if debug {
		log.Printf("Login into %s\n", n.apiURL)
	}
	data := loginRequest{
		Username: username,
		Password: password,
	}

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
	if debug {
		log.Println("Logout...")
	}

	if _, err := n.doRequest("DELETE", "/session", nil, []int{http.StatusOK}); err != nil {
		return err
	}
	n.authCookie = ""
	return nil
}

// ServerProperties will return the current state of the nessus instance.
func (n *Nessus) ServerProperties() (*ServerProperties, error) {
	if debug {
		log.Println("Server properties...")
	}

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
	if debug {
		log.Println("Server status...")
	}

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

const (
	UserTypeLocal = "local"
	UserTypeLDAP  = "ldap"

	Permissions0   = "0"
	Permissions16  = "16"
	Permissions32  = "32"
	Permissions64  = "64"
	Permissions128 = "128"
)

// CreateUser will register a new user with the nessus instance.
// Name and email can be empty.
func (n *Nessus) CreateUser(username, password, userType, permissions, name, email string) (*User, error) {
	if debug {
		log.Println("Creating new user...")
	}
	data := createUserRequest{
		Username:    username,
		Password:    password,
		Permissions: permissions,
		Type:        userType,
	}
	if name != "" {
		data.Name = name
	}
	if email != "" {
		data.Email = email
	}

	resp, err := n.doRequest("POST", "/users", data, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	reply := &User{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// ListUsers will return the list of users on this nessus instance.
func (n *Nessus) ListUsers() (*[]User, error) {
	if debug {
		log.Println("Listing users...")
	}

	resp, err := n.doRequest("GET", "/users", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	reply := &listUsersResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return &reply.Users, nil
}

// DeleteUser will remove a user from this nessus instance.
func (n *Nessus) DeleteUser(userID int) error {
	if debug {
		log.Println("Deleting user...")
	}

	_, err := n.doRequest("DELETE", fmt.Sprintf("/users/%d", userID), nil, []int{http.StatusOK})
	return err
}

// SetUserPassword will change the password for the given user.
func (n *Nessus) SetUserPassword(userID int, password string) error {
	if debug {
		log.Println("Changing password of user...")
	}
	data := setUserPasswordRequest{
		Password: password,
	}

	_, err := n.doRequest("PUT", fmt.Sprintf("/users/%d/chpasswd", userID), data, []int{http.StatusOK})
	return err
}

// EditUser will edit certain information about a user.
// Any non empty parameter will be set.
func (n *Nessus) EditUser(userID int, permissions, name, email string) (*User, error) {
	if debug {
		log.Println("Editing user...")
	}
	data := editUserRequest{}

	if permissions != "" {
		data.Permissions = permissions
	}
	if name != "" {
		data.Name = name
	}
	if email != "" {
		data.Email = email
	}

	resp, err := n.doRequest("PUT", fmt.Sprintf("/users/%d", userID), data, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	reply := &User{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *Nessus) PluginFamilies() ([]PluginFamily, error) {
	if debug {
		log.Println("Getting list of plugin families...")
	}

	resp, err := n.doRequest("GET", "/plugins/families", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	var reply []PluginFamily
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *Nessus) FamilyDetails(ID int64) (*FamilyDetails, error) {
	if debug {
		log.Println("Getting details of family...")
	}

	resp, err := n.doRequest("GET", fmt.Sprintf("/plugins/families/%d", ID), nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	reply := &FamilyDetails{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *Nessus) PluginDetails(ID int64) (*PluginDetails, error) {
	if debug {
		log.Println("Getting details plugin...")
	}

	resp, err := n.doRequest("GET", fmt.Sprintf("/plugins/plugin/%d", ID), nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	reply := &PluginDetails{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *Nessus) Scanners() ([]Scanner, error) {
	if debug {
		log.Println("Getting scanners list...")
	}

	resp, err := n.doRequest("GET", "/scanners", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	var reply []Scanner
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

// AllPlugin wil hammer nessus asking for details of every plugins available and feeding them in
// the returned channel.
// Gettign all the plugins is slow (usually takes a few minutes on a decent machine).
func (n *Nessus) AllPlugins() (chan PluginDetails, error) {
	plugChan := make(chan PluginDetails, 20)

	families, err := n.PluginFamilies()
	if err != nil {
		return nil, err
	}
	idChan := make(chan int64, 20)
	var wgf sync.WaitGroup
	var wgp sync.WaitGroup
	for _, family := range families {
		wgf.Add(1)
		go func(famID int64) {
			defer wgf.Done()
			famDetails, err := n.FamilyDetails(famID)
			if err != nil {
				return
			}
			for _, plugin := range famDetails.Plugins {
				wgp.Add(1)
				idChan <- plugin.ID
			}
		}(family.ID)
	}
	// Launch our worker getting individual plugin details.
	go func() {
		for {
			id, more := <-idChan
			if !more {
				break
			}
			plugin, err := n.PluginDetails(id)
			if err != nil {
				wgp.Done()
				continue
			}
			plugChan <- *plugin
			wgp.Done()
		}
	}()

	go func() {
		wgf.Wait()
		wgp.Wait()
		close(idChan)
		close(plugChan)
	}()

	return plugChan, nil
}

func (n *Nessus) Policies() ([]Policy, error) {
	if debug {
		log.Println("Getting policies list...")
	}

	resp, err := n.doRequest("GET", "/policies", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	var reply listPoliciesResp
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Policies, nil
}

const (
	LaunchOnDemand = "ON_DEMAND"
	LaunchDaily    = "DAILY"
	LaunchWeekly   = "WEEKLY"
	LaunchMonthly  = "MONTHLY"
	LaunchYearly   = "YEARLY"
)

func (n *Nessus) NewScan(
	editorTmplUUID string,
	settingsName string,
	outputFolderID int64,
	policyID int64,
	scannerID int64,
	launch string,
	targets []string) (*Scan, error) {
	if debug {
		log.Println("Creating a new scan...")
	}

	data := newScanRequest{
		UUID: editorTmplUUID,
		Settings: scanSettingsRequest{
			Name:        settingsName,
			Desc:        "Some description",
			FolderID:    outputFolderID,
			ScannerID:   scannerID,
			PolicyID:    policyID,
			Launch:      launch,
			TextTargets: strings.Join(targets, ", "),
		},
	}

	resp, err := n.doRequest("POST", "/scans", data, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	reply := &Scan{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *Nessus) Scans() (*ListScansResponse, error) {
	if debug {
		log.Println("Getting scans list...")
	}

	resp, err := n.doRequest("GET", "/scans", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	reply := &ListScansResponse{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *Nessus) ScanTemplates() ([]Template, error) {
	if debug {
		log.Println("Getting scans templates...")
	}

	resp, err := n.doRequest("GET", "/editor/scans/templates", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	reply := &listTemplatesResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Templates, nil
}

func (n *Nessus) PolicyTemplates() ([]Template, error) {
	if debug {
		log.Println("Getting policy templates...")
	}

	resp, err := n.doRequest("GET", "/editor/policy/templates", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	reply := &listTemplatesResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Templates, nil
}

// StartScan starts the given scan and returns its UUID.
func (n *Nessus) StartScan(scanID int) (string, error) {
	if debug {
		log.Println("Starting scan...")
	}

	resp, err := n.doRequest("POST", fmt.Sprintf("/scans/%d/launch", scanID), nil, []int{http.StatusOK})
	if err != nil {
		return "", err
	}
	reply := &startScanResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return "", err
	}
	return reply.UUID, nil
}

func (n *Nessus) PauseScan(scanID int) error {
	if debug {
		log.Println("Pausing scan...")
	}

	_, err := n.doRequest("POST", fmt.Sprintf("/scans/%d/pause", scanID), nil, []int{http.StatusOK})
	return err
}

func (n *Nessus) ResumeScan(scanID int) error {
	if debug {
		log.Println("Resume scan...")
	}

	_, err := n.doRequest("POST", fmt.Sprintf("/scans/%d/resume", scanID), nil, []int{http.StatusOK})
	return err
}

func (n *Nessus) StopScan(scanID int) error {
	if debug {
		log.Println("Stop scan...")
	}

	_, err := n.doRequest("POST", fmt.Sprintf("/scans/%d/stop", scanID), nil, []int{http.StatusOK})
	return err
}

func (n *Nessus) DeleteScan(scanID int) error {
	if debug {
		log.Println("Deleting scan...")
	}

	_, err := n.doRequest("DELETE", fmt.Sprintf("/scans/%d", scanID), nil, []int{http.StatusOK})
	return err
}

func (n *Nessus) ScanDetails(scanID int) (*ScanDetailsResp, error) {
	if debug {
		log.Println("Getting details about a scan...")
	}

	resp, err := n.doRequest("GET", fmt.Sprintf("/scans/%d", scanID), nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	reply := &ScanDetailsResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (n *Nessus) Timezones() ([]TimeZone, error) {
	if debug {
		log.Println("Getting list of timezones...")
	}

	resp, err := n.doRequest("GET", "/scans/timezones", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	reply := &tzResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Timezones, nil
}

func (n *Nessus) Folders() ([]Folder, error) {
	if debug {
		log.Println("Getting list of folders...")
	}

	resp, err := n.doRequest("GET", "/folders", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	reply := &listFoldersResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Folders, nil
}

func (n *Nessus) CreateFolder(name string) error {
	if debug {
		log.Println("Creating folders...")
	}

	req := createFolderRequest{Name: name}
	_, err := n.doRequest("POST", "/folders", req, []int{http.StatusOK})
	return err
}

func (n *Nessus) EditFolder(folderID int64, newName string) error {
	if debug {
		log.Println("Editing folders...")
	}

	req := editFolderRequest{Name: newName}
	_, err := n.doRequest("PUT", fmt.Sprintf("/folders/%d", folderID), req, []int{http.StatusOK})
	return err
}

func (n *Nessus) DeleteFolder(folderID int64) error {
	if debug {
		log.Println("Deleting folders...")
	}

	_, err := n.doRequest("DELETE", fmt.Sprintf("/folders/%d", folderID), nil, []int{http.StatusOK})
	return err
}

const (
	ExportNessus = "nessus"
	ExportPDF    = "pdf"
	ExportHTML   = "html"
	ExportCSV    = "csv"
	ExportDB     = "db"
)

// ExportsScan exports a scan to a File resource.
// Call ExportStatus to get the status of the export and call Download() to download the actual file.
func (n *Nessus) ExportScan(scanID int64, format string) (int64, error) {
	if debug {
		log.Println("Exporting scan...")
	}

	req := exportScanRequest{Format: format}
	resp, err := n.doRequest("POST", fmt.Sprintf("/scans/%d/export", scanID), req, []int{http.StatusOK})
	if err != nil {
		return 0, err
	}
	reply := &exportScanResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return 0, err
	}
	return reply.File, nil
}

// ExportFinished returns whether the given scan export file has finished being prepared.
func (n *Nessus) ExportFinished(scanID, exportID int64) (bool, error) {
	if debug {
		log.Println("Getting export status...")
	}

	resp, err := n.doRequest("GET", fmt.Sprintf("/scans/%d/export/%d/status", scanID, exportID), nil, []int{http.StatusOK})
	if err != nil {
		return false, err
	}
	reply := &exportStatusResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return false, err
	}
	return reply.Status == "ready", nil
}

// SaveExport will download the given export from nessus.
func (n *Nessus) DownloadExport(scanID, exportID int64) ([]byte, error) {
	if debug {
		log.Println("Downloading export file...")
	}

	resp, err := n.doRequest("GET", fmt.Sprintf("/scans/%d/export/%d/download", scanID, exportID), nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}
	return body, err
}

// TODO: Currently returns a 404... not exposed yet?
func (n *Nessus) ListGroups() ([]Group, error) {
	if debug {
		log.Println("Listing groups...")
	}

	resp, err := n.doRequest("GET", "/groups", nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	reply := &listGroupsResp{}
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply.Groups, nil
}

// TODO: Currently returns a 404... not exposed yet?
func (n *Nessus) CreateGroup(name string) (Group, error) {
	if debug {
		log.Println("Creating a group...")
	}

	req := createGroupRequest{
		Name: name,
	}
	resp, err := n.doRequest("POST", "/groups", req, []int{http.StatusOK})
	if err != nil {
		return Group{}, err
	}
	var reply Group
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return Group{}, err
	}
	return reply, nil
}

func (n *Nessus) Permissions(objectType string, objectID int64) ([]Permission, error) {
	if debug {
		log.Println("Creating a group...")
	}

	resp, err := n.doRequest("GET", fmt.Sprintf("/permissions/%s/%d", objectType, objectID), nil, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}
	var reply []Permission
	if err = json.NewDecoder(resp.Body).Decode(&reply); err != nil {
		return nil, err
	}
	return reply, nil
}
