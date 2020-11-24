package nessie

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type createUserRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Permissions string `json:"permissions"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	Type        string `json:"type"`
}

type setUserPasswordRequest struct {
	Password string `json:"password"`
}

type editUserRequest struct {
	Permissions string `json:"permissions"`
	Name        string `json:"name"`
	Email       string `json:"email"`
}

type NewScanRequest struct {
	UUID     string              `json:"uuid"`
	Settings ScanSettingsRequest `json:"settings"`
}
type ScanSettingsRequest struct {
	Acls           []Acls        `json:"acls"`
	Emails         string        `json:"emails"`
	FilterType     string        `json:"filter_type"`
	Filters        []interface{} `json:"filters"`
	Launch         string        `json:"launch"`
	LaunchNow      bool          `json:"launch_now"`
	Enabled        bool          `json:"enabled"`
	UseDashboard   string        `json:"use_dashboard"`
	Name           string        `json:"name"`
	Description    string        `json:"description"`
	FolderID       int64         `json:"folder_id"`
	ScannerID      int64         `json:"scanner_id"`
	AgentGroupID   []string      `json:"agent_group_id"`
	ScanTimeWindow int64         `json:"scan_time_window"`
	PolicyID       int64         `json:"policy_id"`
	TextTargets    string        `json:"text_targets"`
	FileTargets    string        `json:"file_targets"`
	RRules         string        `json:"rrules"`
	TimeZone       string        `json:"timezone"`
	StartTime      string        `json:"starttime"`
}

type createFolderRequest struct {
	Name string `json:"name"`
}

type editFolderRequest struct {
	Name string `json:"name"`
}

type exportScanRequest struct {
	Format string `json:"format"`
}

type createGroupRequest struct {
	Name string `json:"name"`
}

// CreatePolicyRequest Policies are created by sending the below fields.
type CreatePolicyRequest struct {
	UUID     string         `json:"uuid"`
	Audits   PolicyAudits   `json:"audits"`
	Settings PolicySettings `json:"settings"`
}
type PolicyAudits struct {
	Custom interface{} `json:"custom"`
	Feed   interface{} `json:"feed"`
}
type Acls struct {
	ObjectType  string `json:"object_type"`
	Permissions int    `json:"permissions"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name,omitempty"`
	Name        string `json:"name,omitempty"`
	Owner       int    `json:"owner,omitempty"`
	ID          int    `json:"id,omitempty"`
}
type PolicySettings struct {
	UnixfileanalysisDisableXdev       string `json:"unixfileanalysis_disable_xdev"`
	UnixfileanalysisIncludePaths      string `json:"unixfileanalysis_include_paths"`
	UnixfileanalysisExcludePaths      string `json:"unixfileanalysis_exclude_paths"`
	UnixfileanalysisFileExtensions    string `json:"unixfileanalysis_file_extensions"`
	UnixfileanalysisMaxSize           string `json:"unixfileanalysis_max_size"`
	UnixfileanalysisMaxCumulativeSize string `json:"unixfileanalysis_max_cumulative_size"`
	UnixfileanalysisMaxDepth          string `json:"unixfileanalysis_max_depth"`
	StaggeredStartMins                string `json:"staggered_start_mins"`
	LogWholeAttack                    string `json:"log_whole_attack"`
	EnablePluginDebugging             string `json:"enable_plugin_debugging"`
	AuditTrail                        string `json:"audit_trail"`
	IncludeKb                         string `json:"include_kb"`
	EnablePluginList                  string `json:"enable_plugin_list"`
	AllowPostScanEditing              string `json:"allow_post_scan_editing"`
	WmiNetstatScanner                 string `json:"wmi_netstat_scanner"`
	SSHNetstatScanner                 string `json:"ssh_netstat_scanner"`
	Acls                              []Acls `json:"acls"`
	Name                              string `json:"name"`
	Description                       string `json:"description"`
}

// AuditCustomItem custom audit item
type AuditCustomItem struct {
	Category string `json:"category"`
	File     string `json:"file"`
}
