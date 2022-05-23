package sync

type baseResp struct {
	Code int
	Msg  string
}
type orgRepo struct {
	Org  string `json:"org"`
	Repo string `json:"repo"`
}

type reqIssue struct {
	orgRepo
	Number  string `json:"number"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

type reqComment struct {
	orgRepo
	Number  string `json:"number"`
	Content string `json:"content"`
}

type reqUpdateIssueState struct {
	orgRepo
	Number string `json:"number"`
	State  string `json:"state"`
}

type issueSyncedInfo struct {
	orgRepo
	Number string
	Link   string
}

type issueSyncedResp struct {
	baseResp
	Data issueSyncedInfo
}

type issueSyncedRelation struct {
	IsOrigin         bool   `json:"is_origin"`
	GiteeOrg         string `json:"gitee_org"`
	GiteeRepo        string `json:"gitee_repo"`
	GiteeIssueNumber string `json:"gitee_issue_number"`
	GithubOrg        string `json:"github_org"`
	GithubRepo       string `json:"github_repo"`
	GithubNumber     string `json:"github_number"`
}
