package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cloudflare/pat-app/commands"
	"github.com/urfave/cli"
)

var (
	Version = "0"
	Tag     = "0"
)

func main() {
	app := cli.App{
		Name:                   "pat-app",
		HelpName:               "Private Access Tokens application tool",
		Usage:                  "",
		UsageText:              "",
		ArgsUsage:              "",
		Version:                fmt.Sprintf("%v - %v", Version, Tag),
		Description:            "",
		Commands:               commands.Commands,
		Flags:                  nil,
		EnableBashCompletion:   false,
		HideHelp:               false,
		HideVersion:            false,
		BashComplete:           nil,
		Before:                 nil,
		After:                  nil,
		Action:                 nil,
		CommandNotFound:        nil,
		OnUsageError:           nil,
		Compiled:               time.Time{},
		Authors:                nil,
		Copyright:              "",
		Author:                 "",
		Email:                  "",
		Writer:                 nil,
		ErrWriter:              nil,
		ExitErrHandler:         nil,
		Metadata:               nil,
		ExtraInfo:              nil,
		CustomAppHelpTemplate:  "",
		UseShortOptionHandling: false,
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
