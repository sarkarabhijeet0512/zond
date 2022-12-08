package db

import (
	"github.com/sirupsen/logrus"
	"github.com/theQRL/zond/cmd"
	"github.com/theQRL/zond/runtime/tos"
	validatordb "github.com/theQRL/zond/validator/db"
	"github.com/urfave/cli/v2"
)

var log = logrus.WithField("prefix", "db")

// Commands for interacting with the Prysm validator database.
var Commands = &cli.Command{
	Name:     "db",
	Category: "db",
	Usage:    "defines commands for interacting with the Prysm validator database",
	Subcommands: []*cli.Command{
		{
			Name:        "restore",
			Description: `restores a database from a backup file`,
			Flags: cmd.WrapFlags([]cli.Flag{
				cmd.RestoreSourceFileFlag,
				cmd.RestoreTargetDirFlag,
			}),
			Before: tos.VerifyTosAcceptedOrPrompt,
			Action: func(cliCtx *cli.Context) error {
				if err := validatordb.Restore(cliCtx); err != nil {
					log.WithError(err).Fatal("Could not restore database")
				}
				return nil
			},
		},
		{
			Name:     "migrate",
			Category: "db",
			Usage:    "Defines commands for running validator database migrations",
			Subcommands: []*cli.Command{
				{
					Name:  "up",
					Usage: "Runs up migrations for the validator database",
					Flags: cmd.WrapFlags([]cli.Flag{
						cmd.DataDirFlag,
					}),
					Before: tos.VerifyTosAcceptedOrPrompt,
					Action: func(cliCtx *cli.Context) error {
						if err := validatordb.MigrateUp(cliCtx); err != nil {
							log.WithError(err).Fatal("Could not run database migrations")
						}
						return nil
					},
				},
				{
					Name:  "down",
					Usage: "Runs down migrations for the validator database",
					Flags: cmd.WrapFlags([]cli.Flag{
						cmd.DataDirFlag,
					}),
					Before: tos.VerifyTosAcceptedOrPrompt,
					Action: func(cliCtx *cli.Context) error {
						if err := validatordb.MigrateDown(cliCtx); err != nil {
							log.WithError(err).Fatal("Could not run database migrations")
						}
						return nil
					},
				},
			},
		},
	},
}
