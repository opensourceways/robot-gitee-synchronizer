package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/opensourceways/community-robot-lib/giteeclient"
	"github.com/opensourceways/community-robot-lib/logrusutil"
	liboptions "github.com/opensourceways/community-robot-lib/options"
	"github.com/opensourceways/community-robot-lib/robot-gitee-framework"
	"github.com/opensourceways/community-robot-lib/secret"
	"github.com/sirupsen/logrus"

	"github.com/opensourceways/robot-gitee-synchronizer/sync"
)

type options struct {
	akPath       string
	skPath       string
	region       string
	syncEndpoint string

	service liboptions.ServiceOptions
	gitee   liboptions.GiteeOptions
}

func (o *options) Validate() error {
	if o.region == "" {
		return fmt.Errorf("missing region param")
	}

	if o.syncEndpoint == "" {
		return fmt.Errorf("missing sync-endpoint param")
	}

	if err := o.service.Validate(); err != nil {
		return err
	}

	return o.gitee.Validate()
}

func gatherOptions(fs *flag.FlagSet, args ...string) options {
	var o options

	o.gitee.AddFlags(fs)
	o.service.AddFlags(fs)

	fs.StringVar(&o.akPath, "ak-path", "/etc/ak", "Path to the file containing the HuaweiCloud nlp service Access Key.")
	fs.StringVar(&o.skPath, "sk-path", "/etc/sk", "Path to the file containing the HuaweiCloud nlp service secret Key.")
	fs.StringVar(&o.region, "region", "", "Path to the file containing the HuaweiCloud nlp service region.")
	fs.StringVar(&o.syncEndpoint, "sync-endpoint", "", "the sync agent server api root path")

	fs.Parse(args)
	return o
}

func main() {
	logrusutil.ComponentInit(botName)

	o := gatherOptions(flag.NewFlagSet(os.Args[0], flag.ExitOnError), os.Args[1:]...)
	if err := o.Validate(); err != nil {
		logrus.WithError(err).Fatal("Invalid options")
	}

	secretAgent := new(secret.Agent)
	if err := secretAgent.Start([]string{o.gitee.TokenPath, o.akPath, o.skPath}); err != nil {
		logrus.WithError(err).Fatal("Error starting secret agent.")
	}

	defer secretAgent.Stop()

	c := giteeclient.NewClient(secretAgent.GetTokenGenerator(o.gitee.TokenPath))

	f := func(p string) string {
		return string(secretAgent.GetTokenGenerator(p)())
	}

	v, err := c.GetBot()
	if err != nil {
		logrus.WithError(err).Fatal("Error get bot name")
	}

	bName := strings.ToLower(v.Name)

	syncCli, err := sync.NewSynchronize(o.syncEndpoint, f(o.akPath), f(o.skPath), o.region, c, bName)
	if err != nil {
		logrus.WithError(err).Fatal("error init synchronizer.")
	}

	r := newRobot(syncCli, bName)

	framework.Run(r, o.service)
}
