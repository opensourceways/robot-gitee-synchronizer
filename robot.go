package main

import (
	"fmt"

	"github.com/opensourceways/community-robot-lib/config"
	"github.com/opensourceways/community-robot-lib/robot-gitee-framework"
	sdk "github.com/opensourceways/go-gitee/gitee"
	"github.com/sirupsen/logrus"

	conf "github.com/opensourceways/robot-gitee-synchronizer/config"
	"github.com/opensourceways/robot-gitee-synchronizer/sync"
)

const botName = "synchronizer"

func newRobot(sync sync.Synchronize, name string, ) *robot {
	return &robot{sync: sync, name: name}
}

type robot struct {
	sync sync.Synchronize
	name string
}

func (bot *robot) NewConfig() config.Config {
	return &conf.Configuration{}
}

func (bot *robot) getConfig(cfg config.Config, org, repo string) (*conf.BotConfig, error) {
	c, ok := cfg.(*conf.Configuration)
	if !ok {
		return nil, fmt.Errorf("can't convert to configuration")
	}

	if bc := c.ConfigFor(org, repo); bc != nil {
		return bc, nil
	}

	return nil, fmt.Errorf("no config for this repo:%s/%s", org, repo)
}

func (bot *robot) RegisterEventHandler(f framework.HandlerRegitster) {
	f.RegisterIssueHandler(bot.handleIssueEvent)
	f.RegisterNoteEventHandler(bot.handleNoteEvent)
}

func (bot *robot) handleIssueEvent(e *sdk.IssueEvent, c config.Config, log *logrus.Entry) error {
	org, repo := e.GetOrgRepo()

	cfg, err := bot.getConfig(c, org, repo)
	if err != nil || !cfg.EnableSyncIssue {
		return err
	}

	if e.GetAction() == sdk.ActionOpen {
		return bot.sync.HandleSyncIssueToGitHub(org, repo, e.GetIssue(), cfg)
	}

	if e.GetAction() == "state_change" {
		return bot.sync.HandleSyncIssueStatus(org, repo, e.Issue, cfg)
	}

	return nil
}

func (bot *robot) handleNoteEvent(e *sdk.NoteEvent, c config.Config, log *logrus.Entry) error {
	if !e.IsCreatingCommentEvent() || !e.IsIssue() {
		return nil
	}

	org, repo := e.GetOrgRepo()

	cfg, err := bot.getConfig(c, org, repo)
	if err != nil || !cfg.EnableSyncComment {
		return err
	}

	return bot.sync.HandleSyncIssueComment(org, repo, e, cfg)
}
