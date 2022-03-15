package main

import "github.com/opensourceways/community-robot-lib/config"

type configuration struct {
	ConfigItems []botConfig `json:"config_items,omitempty"`
}

func (c *configuration) configFor(org, repo string) *botConfig {
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

func (c *configuration) Validate() error {
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

func (c *configuration) SetDefault() {
	if c == nil {
		return
	}

	Items := c.ConfigItems
	for i := range Items {
		Items[i].setDefault()
	}
}

type botConfig struct {
	config.RepoFilter
	// EnableSyncIssue control whether synchronization issues, default false.
	EnableSyncIssue bool `json:"enable_sync_issue,omitempty"`
	// EnableSyncComment control whether synchronization comments, default false.
	EnableSyncComment bool `json:"enable_sync_comment,omitempty"`
	// DoNotSyncAuthors the person configured by this configuration item as the author of
	// the issue or comment will not need to synchronize.
	// in addition, if it is empty the current robot account is default.
	DoNotSyncAuthors []string `json:"do_not_sync_authors,omitempty"`
}

func (c *botConfig) setDefault() {
}

func (c *botConfig) validate() error {
	return c.RepoFilter.Validate()
}
