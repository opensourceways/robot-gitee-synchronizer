package sync

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	nlp "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/nlp/v2"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/nlp/v2/model"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/nlp/v2/region"
	"github.com/opensourceways/community-robot-lib/utils"
	sdk "github.com/opensourceways/go-gitee/gitee"
	"github.com/sirupsen/logrus"
)

const (
	syncIssueEndPoint   = "/synchronization/github/issue"
	syncCommentEndPoint = "/synchronization/github/comment"
	syncedIssueMsg      = `**SYNCED PROMPT:**  current issue has been synced with [it](%s) <!--- %s -->`
)

type giteeCli interface {
	CreateIssueComment(org, repo string, number string, comment string) error
}

// Synchronizer the sync calling the sync service
type Synchronizer struct {
	utils.HttpClient

	nlpCli *nlp.NlpClient
	gc     giteeCli

	// Endpoint the root path of the request
	Endpoint *url.URL
}

// HandleSyncIssueToGitHub synchronize the Issue of the gitee platform to the Github platform
func (sc *Synchronizer) HandleSyncIssueToGitHub(org, repo string, e *sdk.IssueHook) error {
	title, err := sc.translateToEnglish(e.GetTitle())
	if err != nil {
		title = e.GetTitle()
		logrus.Error(err)
	}

	content, err := sc.translateToEnglish(e.GetBody())
	if err != nil {
		content = e.GetBody()
		logrus.Error(err)
	}

	issue := reqIssue{
		orgRepo: orgRepo{Org: "xwz123", Repo: "test"},
		Title:   title,
		Content: content,
	}

	v, err := sc.createGithubIssue(issue)
	if err != nil {
		return err
	}

	return sc.addIssueSyncedMsg(org, repo, v, e)
}

// HandleSyncIssueComment synchronize the comments of the gitee platform Issue to the Github platform
func (sc *Synchronizer) HandleSyncIssueComment(org, repo string, e *sdk.NoteHook) error {
	return nil
}

func (sc *Synchronizer) addIssueSyncedMsg(org, repo string, si *issueSyncedInfo, issue *sdk.IssueHook) error {
	isr := issueSyncedRelation{
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

	var mErr utils.MultiError

	hubComment := fmt.Sprintf(syncedIssueMsg, issue.GetHtmlUrl(), ds)
	teeComment := fmt.Sprintf(syncedIssueMsg, si.Link, ds)

	mErr.AddError(sc.createGithubComment(reqComment{
		orgRepo: orgRepo{si.Org, si.Repo},
		Number:  si.Number,
		Content: hubComment,
	}))

	mErr.AddError(sc.gc.CreateIssueComment(
		org,
		repo,
		issue.GetNumber(),
		teeComment,
	))

	return mErr.Err()
}

func (sc *Synchronizer) createGithubComment(comment reqComment) error {
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

func (sc *Synchronizer) createGithubIssue(issue reqIssue) (*issueSyncedInfo, error) {
	payload, err := utils.JsonMarshal(&issue)
	if err != nil {
		return nil, err
	}

	uri := sc.getCallURL( syncIssueEndPoint)

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

func (sc *Synchronizer) forwardTo(req *http.Request, jrp interface{}) error {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "gitte-synchronizer")

	return sc.ForwardTo(req, jrp)
}

func (sc *Synchronizer) translateToEnglish(text string) (string, error) {
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

func (sc *Synchronizer) getCallURL(p string) string {
	v := *sc.Endpoint
	v.Path = path.Join(v.Path, p)

	return v.String()
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

func NewSynchronize(syncSrvAddr, ak, sk, reg string, gc giteeCli) (Synchronizer, error) {
	url, err := url.Parse(syncSrvAddr)
	if err != nil {
		return Synchronizer{}, err
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

	return Synchronizer{
		gc:         gc,
		Endpoint:   url,
		HttpClient: utils.HttpClient{MaxRetries: 3},
		nlpCli:     client,
	}, nil
}
