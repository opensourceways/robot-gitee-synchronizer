package main

import (
	"fmt"
	"strings"

	"github.com/opensourceways/community-robot-lib/config"
	"github.com/opensourceways/community-robot-lib/robot-gitee-framework"
	sdk "github.com/opensourceways/go-gitee/gitee"
	"github.com/sirupsen/logrus"

	"github.com/opensourceways/robot-gitee-synchronizer/sync"
)

const botName = "synchronizer"

func newRobot(sync sync.Synchronizer, name string, ) *robot {
	return &robot{sync: sync, name: name}
}

type robot struct {
	sync sync.Synchronizer
	name string
}

func (bot *robot) NewConfig() config.Config {
	return &configuration{}
}

func (bot *robot) getConfig(cfg config.Config, org, repo string) (*botConfig, error) {
	c, ok := cfg.(*configuration)
	if !ok {
		return nil, fmt.Errorf("can't convert to configuration")
	}

	if bc := c.configFor(org, repo); bc != nil {
		return bc, nil
	}

	return nil, fmt.Errorf("no config for this repo:%s/%s", org, repo)
}

func (bot *robot) RegisterEventHandler(f framework.HandlerRegitster) {
	f.RegisterIssueHandler(bot.handleIssueEvent)
	f.RegisterNoteEventHandler(bot.handleNoteEvent)
}

func (bot *robot) handleIssueEvent(e *sdk.IssueEvent, c config.Config, log *logrus.Entry) error {
	if e.GetAction() != sdk.ActionOpen {
		return nil
	}

	org, repo := e.GetOrgRepo()

	cfg, err := bot.getConfig(c, org, repo)
	if err != nil || !cfg.EnableSyncIssue {
		return err
	}

	if !bot.needSync(cfg, e.GetIssueAuthor()) {
		log.Info("not need sync")
		return nil
	}

	return bot.sync.HandleSyncIssueToGitHub(org, repo, e.GetIssue())
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

	if !bot.needSync(cfg, e.GetCommenter()) {
		return nil
	}

	// TODO: exec sync logic
	return nil
}

func (bot *robot) needSync(cfg *botConfig, author string) bool {
	if len(cfg.DoNotSyncAuthors) == 0 {
		return strings.ToLower(author) != bot.name
	}

	for _, v := range cfg.DoNotSyncAuthors {
		if strings.ToLower(v) == botName {
			return false
		}
	}

	return true
}
