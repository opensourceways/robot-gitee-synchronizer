package config

import (
	"fmt"
	"regexp"

	"github.com/opensourceways/community-robot-lib/config"
)

type Configuration struct {
	ConfigItems []BotConfig `json:"config_items,omitempty"`
}

func (c *Configuration) ConfigFor(org, repo string) *BotConfig {
	if c == nil {
		return nil
	}

	items := c.ConfigItems
	v := make([]config.IRepoFilter, len(items))
	for i := range items {
		v[i] = &items[i]
	}

	if i := config.Find(org, repo, v); i >= 0 {
		return &items[i]
	}

	return nil
}

func (c *Configuration) Validate() error {
	if c == nil {
		return nil
	}

	items := c.ConfigItems
	for i := range items {
		if err := items[i].validate(); err != nil {
			return err
		}
	}

	return nil
}

func (c *Configuration) SetDefault() {
	if c == nil {
		return
	}

	Items := c.ConfigItems
	for i := range Items {
		Items[i].setDefault()
	}
}

type BotConfig struct {
	config.RepoFilter
	// EnableSyncIssue control whether synchronization issues, default false.
	EnableSyncIssue bool `json:"enable_sync_issue,omitempty"`
	// EnableSyncComment control whether synchronization comments, default false.
	EnableSyncComment bool `json:"enable_sync_comment,omitempty"`
	// DoNotSyncAuthors the person configured by this Configuration item as the author of
	// the issue or comment will not need to synchronize.
	// in addition, if it is empty the current robot account is default.
	DoNotSyncAuthors []NotSyncConfig `json:"do_not_sync_authors,omitempty"`
	// SyncOrgMapping mappings of organizations that need to perform synchronization.
	SyncOrgMapping map[string]string `json:"sync_org_mapping,omitempty"`
}

func (c *BotConfig) setDefault() {
}

func (c *BotConfig) validate() error {
	for _, v := range c.DoNotSyncAuthors {
		if err := v.validate(); err != nil {
			return err
		}
	}

	return c.RepoFilter.Validate()
}

func (c *BotConfig) OrgMapping(org string) string {
	if len(c.SyncOrgMapping) == 0 {
		return org
	}

	if v, ok := c.SyncOrgMapping[org]; ok {
		return v
	}

	return org
}

type NotSyncConfig struct {
	// Account the login account name of the platform where the user is located.
	Account string `json:"account" required:"true"`
	// IssueCommentContentWhitelist the account Configuration item specifies a regular whitelist of user comment content,
	// and comments that match the regular pattern will be synchronized.
	IssueCommentContentWhitelist []string `json:"issue_comment_content_whitelist,omitempty"`
	// NeedSyncIssue whether the issue created by the person specified by the account Configuration item needs to be synchronized.
	NeedSyncIssue bool `json:"need_sync_issue,omitempty"`
}


func (nc NotSyncConfig) CommentContentInWhitelist(content string) bool {
	for _, v := range nc.IssueCommentContentWhitelist {
		if reg, err := regexp.Compile(v); err == nil && reg.MatchString(content) {
			return true
		}
	}

	return false
}

func (nc NotSyncConfig) validate() error {
	if nc.Account == "" {
		return fmt.Errorf("the account Configuration item cannot be empty")
	}

	for _, v := range nc.IssueCommentContentWhitelist {
		if _, err := regexp.Compile(v); err != nil {
			return fmt.Errorf("%s compiles the regular error: %v", v, err)
		}
	}

	return nil
}
