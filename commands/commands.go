package commands

import (
	"github.com/urfave/cli"
)

var Commands = []cli.Command{
	{
		Name:   "issuer",
		Usage:  "Start a PAT issuer",
		Action: startIssuer,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:     "cert, c",
				Value:    "",
				Required: true,
			},
			cli.StringFlag{
				Name:     "key, k",
				Value:    "",
				Required: true,
			},
			cli.StringFlag{
				Name:     "name",
				Value:    "",
				Required: true,
			},
			cli.StringFlag{
				Name:  "port",
				Value: "443",
			},
			cli.StringSliceFlag{
				Name:  "origins",
				Usage: "Supported origins",
			},
			cli.StringFlag{
				Name:  "log",
				Value: "error",
			},
		},
	},
	{
		Name:   "attester",
		Usage:  "Start a PAT attester",
		Action: startAttester,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:     "cert, c",
				Value:    "",
				Required: true,
			},
			cli.StringFlag{
				Name:     "key, k",
				Value:    "",
				Required: true,
			},
			cli.StringFlag{
				Name:  "port",
				Value: "443",
			},
			cli.StringFlag{
				Name:  "log",
				Value: "error",
			},
		},
	},
	{
		Name:   "origin",
		Usage:  "Start a PAT origin",
		Action: startOrigin,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:     "cert, c",
				Value:    "",
				Required: true,
			},
			cli.StringFlag{
				Name:     "key, k",
				Value:    "",
				Required: true,
			},
			cli.StringFlag{
				Name:  "port",
				Value: "443",
			},
			cli.StringFlag{
				Name:     "issuer",
				Value:    "",
				Required: true,
			},
			cli.StringFlag{
				Name:     "name",
				Value:    "",
				Required: true,
			},
			cli.StringFlag{
				Name:  "log",
				Value: "error",
			},
		},
	},
	{
		Name:   "fetch",
		Usage:  "Fetch a resource protected using PAT",
		Action: runClientFetch,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "id",
				Value: "default",
			},
			cli.StringFlag{
				Name:     "origin",
				Value:    "",
				Required: true,
			},
			cli.StringFlag{
				Name:  "secret",
				Value: "",
			},
			cli.StringFlag{
				Name:     "attester",
				Value:    "",
				Required: true,
			},
			cli.StringFlag{
				Name:  "resource",
				Value: "/index.html",
			},
			cli.StringFlag{
				Name:  "store",
				Value: "",
			},
			cli.IntFlag{
				Name:  "count",
				Value: 1,
			},
			cli.BoolFlag{
				Name:  "non-interactive",
				Usage: "Flag to request non-interactive tokens",
			},
			cli.BoolFlag{
				Name:  "cross-origin",
				Usage: "Flag to request cross-origin tokens",
			},
			cli.StringFlag{
				Name:  "token-type",
				Usage: "Type of token protocol requested ['basic', 'rate-limited'], defaults to 'rate-limited'",
			},
			cli.StringFlag{
				Name:  "log",
				Value: "error",
			},
		},
	},
	{
		Name:   "test",
		Usage:  "Run through test cases for all possible token challenges",
		Action: runRunner,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "id",
				Value: "default",
			},
			cli.StringFlag{
				Name:     "origin",
				Value:    "",
				Required: true,
			},
			cli.StringFlag{
				Name:  "secret",
				Value: "",
			},
			cli.StringFlag{
				Name:     "attester",
				Value:    "",
				Required: true,
			},
			cli.StringFlag{
				Name:  "resource",
				Value: "/index.html",
			},
		},
	},
}
