package nessie

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoRequest(t *testing.T) {
	// Test structure to be serialized.
	type payload struct {
		A int `json:"a"`
	}
	authToken := "some token"
	var tests = []struct {
		method       string
		resource     string
		sentPayload  payload
		wantPayload  string
		serverStatus int
		wantStatus   []int
		wantError    bool
	}{
		// All succeeding methods.
		{"GET", "/test", payload{}, "{\"a\":0}", http.StatusOK, []int{http.StatusOK}, false},
		{"POST", "/test", payload{}, "{\"a\":0}", http.StatusOK, []int{http.StatusOK}, false},
		{"DELETE", "/test", payload{}, "{\"a\":0}", http.StatusOK, []int{http.StatusOK}, false},
		{"PUT", "/test", payload{}, "{\"a\":0}", http.StatusOK, []int{http.StatusOK}, false},
		// Payload test.
		{"GET", "/test", payload{42}, "{\"a\":42}", http.StatusOK, []int{http.StatusOK}, false},
		// Expected failure.
		{"POST", "/test", payload{}, "{\"a\":0}", http.StatusInternalServerError, []int{http.StatusInternalServerError}, false},
		// Unexpected failure
		{"POST", "/test", payload{}, "{\"a\":0}", http.StatusInternalServerError, []int{http.StatusOK}, true},
	}
	for _, tt := range tests {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tt.serverStatus)
			if r.Header.Get("X-Cookie") != fmt.Sprintf("token=%s", authToken) {
				t.Errorf("invalid auth header, got=%s, want=%s", r.Header.Get("X-Cookie"), authToken)
			}
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Errorf("could not read request body: %v", err)
				return
			}
			bodyStr := string(body)
			if bodyStr != tt.wantPayload {
				t.Errorf("unexpected payload, got=%s, want=%s", body, tt.wantPayload)
			}
		}))
		n, err := NewInsecureNessus(ts.URL)
		n.Verbose = true
		if err != nil {
			t.Errorf("could not create nessie instance: %v (%+v)", err, tt)
			continue
		}
		// Increase covered lines.
		n.authCookie = authToken
		resp, err := n.doRequest(tt.method, tt.resource, tt.sentPayload, tt.wantStatus)
		if tt.wantError {
			if err == nil {
				t.Errorf("got no error, expected one (%+v)", tt)
			}
			continue
		}
		if err != nil {
			t.Errorf("error in doRequest: %v (%+v)", err, tt)
			continue
		}
		if resp.StatusCode != tt.serverStatus {
			t.Errorf("got status code=%d, wanted=%d", resp.StatusCode, tt.serverStatus)
		}
	}
}

func TestLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")
		j, err := json.Marshal(&loginResp{Token: "some token"})
		if err != nil {
			t.Fatalf("cannot serialize login response: %v", err)
		}
		w.Write(j)
	}))
	defer server.Close()
	n, err := NewInsecureNessus(server.URL)
	if err != nil {
		t.Fatalf("cannot create nessus instance: %v", err)
	}

	if err := n.Login("username", "password"); err != nil {
		t.Fatalf("got error during login: %v", err)
	}
	if got, want := n.authCookie, "some token"; got != want {
		t.Fatalf("wrong auth cookie, got=%q, want=%q", got, want)
	}
}

func TestMethods(t *testing.T) {
	var tests = []struct {
		resp       interface{}
		statusCode int
		call       func(n *Nessus)
	}{
		{&Session{}, http.StatusOK, func(n *Nessus) { n.Session() }},
		{&ServerProperties{}, http.StatusOK, func(n *Nessus) { n.ServerProperties() }},
		{&ServerStatus{}, http.StatusOK, func(n *Nessus) { n.ServerStatus() }},
		{&User{}, http.StatusOK, func(n *Nessus) {
			n.CreateUser("username", "pass", UserTypeLocal, Permissions32, "name", "email@foo.com")
		}},
		{&listUsersResp{}, http.StatusOK, func(n *Nessus) { n.ListUsers() }},
		{nil, http.StatusOK, func(n *Nessus) { n.DeleteUser(42) }},
		{nil, http.StatusOK, func(n *Nessus) { n.SetUserPassword(42, "newpass") }},
		{&User{}, http.StatusOK, func(n *Nessus) {
			n.EditUser(42, Permissions128, "newname", "newmain@goo.fom")
		}},
		{[]PluginFamily{}, http.StatusOK, func(n *Nessus) { n.PluginFamilies() }},
		{&FamilyDetails{}, http.StatusOK, func(n *Nessus) { n.FamilyDetails(42) }},
		{&PluginDetails{}, http.StatusOK, func(n *Nessus) { n.PluginDetails(42) }},
		{[]Scanner{}, http.StatusOK, func(n *Nessus) { n.Scanners() }},
		{&listPoliciesResp{}, http.StatusOK, func(n *Nessus) { n.Policies() }},
		{&Scan{}, http.StatusOK, func(n *Nessus) {
			n.NewScan("editorUUID", "settingsName", 42, 43, 44, LaunchDaily, []string{"target1", "target2"})
		}},
		{&ListScansResponse{}, http.StatusOK, func(n *Nessus) { n.Scans() }},
		{[]Template{}, http.StatusOK, func(n *Nessus) { n.ScanTemplates() }},
		{[]Template{}, http.StatusOK, func(n *Nessus) { n.PolicyTemplates() }},
		{"id", http.StatusOK, func(n *Nessus) { n.StartScan(42) }},
		{nil, http.StatusOK, func(n *Nessus) { n.PauseScan(42) }},
		{nil, http.StatusOK, func(n *Nessus) { n.ResumeScan(42) }},
		{nil, http.StatusOK, func(n *Nessus) { n.StopScan(42) }},
		{&ScanDetailsResp{}, http.StatusOK, func(n *Nessus) { n.ScanDetails(42) }},
		{[]TimeZone{}, http.StatusOK, func(n *Nessus) { n.Timezones() }},
		{[]Folder{}, http.StatusOK, func(n *Nessus) { n.Folders() }},
		{nil, http.StatusOK, func(n *Nessus) { n.CreateFolder("name") }},
		{nil, http.StatusOK, func(n *Nessus) { n.EditFolder(42, "newname") }},
		{nil, http.StatusOK, func(n *Nessus) { n.DeleteFolder(42) }},
		{42, http.StatusOK, func(n *Nessus) { n.ExportScan(42, ExportPDF) }},
		{true, http.StatusOK, func(n *Nessus) { n.ExportFinished(42, 43) }},
		{[]byte("raw export"), http.StatusOK, func(n *Nessus) { n.DownloadExport(42, 43) }},
		{[]Permission{}, http.StatusOK, func(n *Nessus) { n.Permissions("scanner", 42) }},
	}
	for _, tt := range tests {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tt.statusCode)
			if tt.resp != nil {
				j, err := json.Marshal(tt.resp)
				if err != nil {
					t.Fatalf("cannot serialize response: %v", err)
				}
				w.Write(j)
			}
		}))
		defer server.Close()
		n, err := NewInsecureNessus(server.URL)
		if err != nil {
			t.Fatalf("cannot create nessus instance: %v", err)
		}
		n.Verbose = true
		tt.call(n)
	}
}
