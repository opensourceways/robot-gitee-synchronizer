package sync

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	nlp "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/nlp/v2"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/nlp/v2/model"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/nlp/v2/region"
	"github.com/opensourceways/community-robot-lib/utils"
	sdk "github.com/opensourceways/go-gitee/gitee"
	"github.com/sirupsen/logrus"

	"github.com/opensourceways/robot-gitee-synchronizer/config"
)

const (
	syncIssueEndPoint    = "/synchronization/github/issue"
	syncCommentEndPoint  = "/synchronization/github/comment"
	syncedIssueComment   = `**SYNCED PROMPT:**  This issue has been synchronized with [another issue](%s). <!--- %s -->`
	syncedIssueNotice    = `> Note: this issue is create by %s at %s . The content may be translated from other languages. You can still comment on this issue and the author will be notified.`
	syncedCommentContent = `> %s create at %s

%s
`
)

var (
	syncedInfoReg           = regexp.MustCompile(`<!--- (.*) -->`)
	syncIssueMsgReg         = regexp.MustCompile(fmt.Sprintf(`\*\*SYNCED PROMPT:\*\*  This issue has been synchronized with \[another issue\]\(%s\). <!--- %s -->`, "(.*)", "(.*)"))
	syncedCommentContentReg = regexp.MustCompile(fmt.Sprintf(`> %s create at %s\n\n%s`, "(.*)", "(.*)", "(.*)"))
	syncedIssueContentReg   = regexp.MustCompile(fmt.Sprintf(syncedIssueNotice, "(.*)", "(.*)"))
	checkIssueIDReg         = regexp.MustCompile(`#[0-9a-zA-Z]+\b`)
)

type giteeCli interface {
	CreateIssueComment(org, repo string, number string, comment string) error
	ListIssueComments(org, repo, number string) ([]sdk.Note, error)
	GetIssue(org, repo, number string) (sdk.Issue, error)
}

// Synchronize the sync calling the sync service
type Synchronize struct {
	utils.HttpClient

	nlpCli *nlp.NlpClient
	gc     giteeCli

	// Endpoint the root path of the request
	Endpoint     *url.URL
	synchronizer string
}

// HandleSyncIssueToGitHub synchronize the Issue of the gitee platform to the Github platform
func (sc *Synchronize) HandleSyncIssueToGitHub(org, repo string, e *sdk.IssueHook, cfg *config.BotConfig) error {
	if !sc.needSyncIssue(cfg, e) {
		logrus.Infof("Issue %s does't need to be synchronized", org, repo, e.GetHtmlUrl())

		return nil
	}

	title, err := sc.translateToEnglish(e.GetTitle())
	if err != nil {
		title = e.GetTitle()
		logrus.Error(err)
	}

	content := sc.processIssueIDInContent(org, repo, e.GetBody())

	content, err = sc.translateToEnglish(content)
	if err != nil {
		content = e.GetBody()
		logrus.Error(err)
	}

	om := cfg.OrgMapping(org)
	issue := reqIssue{
		orgRepo: orgRepo{Org: om, Repo: repo},
		Title:   title,
		Content: combinedIssueContent(content, e),
	}

	v, err := sc.createGithubIssue(issue)
	if err != nil {
		return err
	}

	return sc.addIssueSyncedMsg(org, repo, v, e)
}

// HandleSyncIssueComment synchronize the comments of the gitee platform Issue to the Github platform
func (sc *Synchronize) HandleSyncIssueComment(org, repo string, e *sdk.NoteEvent, cfg *config.BotConfig) error {
	if !sc.needSyncIssueComment(cfg, e.GetComment()) {
		logrus.Info("Comment %s does't need to be synchronized", e.GetComment().GetHtmlUrl())

		return nil
	}

	info, err := sc.findSyncedIssueInfoFromComments(org, repo, e.GetIssueNumber())
	if err != nil {
		return err
	}

	comment := sc.processIssueIDInContent(org, repo, e.GetComment().GetBody())

	comment, err = sc.translateToEnglish(comment)
	if err != nil {
		return err
	}

	req := reqComment{
		orgRepo: orgRepo{Org: info.GithubOrg, Repo: info.GithubRepo},
		Number:  info.GithubNumber,
		Content: combinedIssueCommentContent(comment, e.GetComment()),
	}

	return sc.createGithubComment(req)
}

func (sc *Synchronize) addIssueSyncedMsg(org, repo string, si *issueSyncedInfo, issue *sdk.IssueHook) error {
	var mErr utils.MultiError
	var isr = issueSyncedRelation{
		GiteeOrg:         org,
		GiteeRepo:        repo,
		GiteeIssueNumber: issue.GetNumber(),
		GithubOrg:        si.Org,
		GithubRepo:       si.Repo,
		GithubNumber:     si.Number,
	}

	ds, err := encodeObject(&isr)
	if err != nil {
		return err
	}

	hubComment := fmt.Sprintf(syncedIssueComment, issue.GetHtmlUrl(), ds)
	mErr.AddError(sc.createGithubComment(reqComment{
		orgRepo: orgRepo{si.Org, si.Repo},
		Number:  si.Number,
		Content: hubComment,
	}))

	isr.IsOrigin = true
	ds, err = encodeObject(&isr)
	if err != nil {
		return err
	}

	teeComment := fmt.Sprintf(syncedIssueComment, si.Link, ds)
	mErr.AddError(sc.gc.CreateIssueComment(
		org,
		repo,
		issue.GetNumber(),
		teeComment,
	))

	return mErr.Err()
}

func (sc *Synchronize) createGithubComment(comment reqComment) error {
	payload, err := utils.JsonMarshal(&comment)
	if err != nil {
		return err
	}
	uri := sc.getCallURL(syncCommentEndPoint)

	req, err := http.NewRequest(http.MethodPost, uri, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	return sc.forwardTo(req, nil)
}

func (sc *Synchronize) createGithubIssue(issue reqIssue) (*issueSyncedInfo, error) {
	payload, err := utils.JsonMarshal(&issue)
	if err != nil {
		return nil, err
	}

	uri := sc.getCallURL(syncIssueEndPoint)

	req, err := http.NewRequest(http.MethodPost, uri, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	var resp issueSyncedResp
	if err := sc.forwardTo(req, &resp); err != nil {
		return nil, err
	}

	return &resp.Data, nil
}

func (sc *Synchronize) forwardTo(req *http.Request, jrp interface{}) error {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "gitte-synchronizer")

	return sc.ForwardTo(req, jrp)
}

func (sc *Synchronize) translateToEnglish(text string) (string, error) {
	if text == "" {
		return "", nil
	}

	request := &model.RunTextTranslationRequest{}
	request.Body = &model.TextTranslationReq{
		To:   model.GetTextTranslationReqToEnum().EN,
		From: model.GetTextTranslationReqFromEnum().AUTO,
		Text: text,
	}
	response, err := sc.nlpCli.RunTextTranslation(request)
	if err != nil {
		return "", err
	}

	if response.ErrorCode != nil || response.ErrorMsg != nil {
		return "", fmt.Errorf("translate appear error errcode: %s errcode: %s", *response.ErrorCode, *response.ErrorMsg)
	}

	return *response.TranslatedText, nil
}

func (sc *Synchronize) getCallURL(p string) string {
	v := *sc.Endpoint
	v.Path = path.Join(v.Path, p)

	return v.String()
}

func (sc *Synchronize) findSyncedIssueInfoFromComments(org, repo, number string) (*issueSyncedRelation, error) {
	comments, err := sc.gc.ListIssueComments(org, repo, number)
	if err != nil {
		return nil, err
	}

	for _, v := range comments {
		if si, b := parserSyncedIssueInfo(v); b {
			return si, nil
		}
	}

	return nil, fmt.Errorf("PR %s/%s/%s is not synced", org, repo, number)
}

func (sc *Synchronize) needSyncIssue(cfg *config.BotConfig, issue *sdk.IssueHook) bool {
	if !cfg.EnableSyncIssue {
		return false
	}

	author := issue.GetUser().GetLogin()
	if sc.isCreateSyncIssue(issue.GetBody(), author) {
		return false
	}

	nsc := sc.getDoNotSyncByAuthor(cfg, author)
	if nsc == nil {
		return true
	}

	return nsc.NeedSyncIssue
}

func (sc *Synchronize) isCreateSyncIssue(body, author string) bool {
	if strings.ToLower(author) != sc.synchronizer {
		return false
	}

	return syncedIssueContentReg.MatchString(body)
}

func (sc *Synchronize) needSyncIssueComment(cfg *config.BotConfig, comment *sdk.NoteHook) bool {
	if !cfg.EnableSyncComment {
		return false
	}

	author := comment.GetUser().GetLogin()
	body := comment.GetBody()

	if sc.isCreateSyncIssueComment(body, author) {
		return false
	}

	nsc := sc.getDoNotSyncByAuthor(cfg, author)
	if nsc == nil {
		return true
	}

	return nsc.CommentContentInWhitelist(body)
}

func (sc *Synchronize) isCreateSyncIssueComment(body, author string) bool {
	if strings.ToLower(author) != sc.synchronizer {
		return false
	}

	return syncedCommentContentReg.MatchString(body)
}

func (sc *Synchronize) getDoNotSyncByAuthor(cfg *config.BotConfig, author string) (nsc *config.NotSyncConfig) {
	for i := range cfg.DoNotSyncAuthors {
		tmp := cfg.DoNotSyncAuthors[i]
		if strings.ToLower(author) == strings.ToLower(tmp.Account) {
			nsc = &tmp

			return
		}
	}

	if strings.ToLower(author) == sc.synchronizer {
		nsc = &config.NotSyncConfig{Account: sc.synchronizer}
	}

	return
}

func (sc *Synchronize) HandleSyncIssueStatus(org, repo string, issue *sdk.IssueHook, cfg *config.BotConfig) error {
	if !cfg.EnableSyncIssue {
		return nil
	}

	info, err := sc.findSyncedIssueInfoFromComments(org, repo, issue.GetNumber())
	if err != nil {
		return err
	}

	if !info.IsOrigin {
		logrus.Infof("issue %s is not sync origin no need sync status", issue.GetHtmlUrl())

		return nil
	}

	state := ""
	switch issue.GetState() {
	case "open", "progressing":
		state = "open"
	case "closed", "rejected":
		state = "closed"
	default:
		return fmt.Errorf("unknow issue state error")
	}

	p := reqUpdateIssueState{
		orgRepo: orgRepo{info.GithubOrg, info.GithubRepo},
		Number:  info.GithubNumber,
		State:   state,
	}

	payload, err := utils.JsonMarshal(&p)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, sc.getCallURL(syncIssueEndPoint), bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	return sc.forwardTo(req, nil)
}

func (sc *Synchronize) processIssueIDInContent(org, repo, content string) string {
	matches := checkIssueIDReg.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return content
	}

	for _, v := range matches {
		if len(v) > 0 {
			iid := v[0]
			tIID := sc.transformIssueID(org, repo, iid)

			content = strings.Replace(content, iid, tIID, 1)
		}
	}

	return content
}

func (sc *Synchronize) transformIssueID(org, repo, issueID string) string {
	number := strings.Trim(issueID, "#")
	if len(number) != 6 {
		return fmt.Sprintf("#<!--- -->%s", number)
	}

	issue, err := sc.gc.GetIssue(org, repo, number)
	if err != nil || issue.Number == "" {
		return fmt.Sprintf("#<!--- -->%s", number)
	}

	c, err := sc.findSyncedIssueInfoFromComments(org, repo, issue.Number)
	if err != nil || c == nil {
		return fmt.Sprintf("[#<!--- -->%s](%s)", number, issue.HtmlUrl)
	}

	return fmt.Sprintf("#%s", c.GithubNumber)
}

func combinedIssueContent(content string, e *sdk.IssueHook) string {
	contentTpl := `%s

%s
`
	author := fmt.Sprintf("[%s](%s)", e.GetUser().GetName(), e.GetUser().GetHtmlURL())
	platform := fmt.Sprintf("[gitee](%s)", e.GetHtmlUrl())

	notice := fmt.Sprintf(syncedIssueNotice, author, platform)

	return fmt.Sprintf(contentTpl, notice, content)
}

func combinedIssueCommentContent(content string, e *sdk.NoteHook) string {
	author := fmt.Sprintf("[%s](%s)", e.GetUser().GetName(), e.GetUser().GetHtmlURL())
	platform := fmt.Sprintf("[gitee](%s)", e.GetHtmlUrl())

	return fmt.Sprintf(syncedCommentContent, author, platform, content)
}

func parserSyncedIssueInfo(comment sdk.Note) (*issueSyncedRelation, bool) {
	body := comment.Body
	if !syncIssueMsgReg.MatchString(body) {
		return nil, false
	}

	matches := syncedInfoReg.FindAllStringSubmatch(body, -1)
	if len(matches) != 1 || len(matches[0]) != 2 {
		return nil, false
	}

	infoStr := matches[0][1]
	info := new(issueSyncedRelation)

	if err := decodeObject(infoStr, info); err != nil {
		logrus.WithError(err).Error("parse synced issue info fail")

		return nil, false
	}

	return info, true
}

func encodeObject(data interface{}) (string, error) {
	marshal, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(marshal), nil
}

func decodeObject(data string, obj interface{}) error {
	ds, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return err
	}

	return json.Unmarshal(ds, obj)
}

func NewSynchronize(syncSrvAddr, ak, sk, reg string, gc giteeCli, synchronizer string) (Synchronize, error) {
	uri, err := url.Parse(syncSrvAddr)
	if err != nil {
		return Synchronize{}, err
	}

	auth := basic.NewCredentialsBuilder().
		WithAk(ak).
		WithSk(sk).
		Build()

	client := nlp.NewNlpClient(nlp.NlpClientBuilder().
		WithRegion(region.ValueOf(reg)).
		WithCredential(auth).
		Build(),
	)

	return Synchronize{
		gc:           gc,
		Endpoint:     uri,
		HttpClient:   utils.HttpClient{MaxRetries: 3},
		nlpCli:       client,
		synchronizer: synchronizer,
	}, nil
}
