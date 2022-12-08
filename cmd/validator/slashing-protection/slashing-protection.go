package historycmd

import (
	"github.com/sirupsen/logrus"
	"github.com/theQRL/zond/cmd"
	"github.com/theQRL/zond/cmd/validator/flags"
	"github.com/theQRL/zond/config/features"
	"github.com/theQRL/zond/runtime/tos"
	"github.com/urfave/cli/v2"
)

// Commands for slashing protection.
var Commands = &cli.Command{
	Name:     "slashing-protection-history",
	Category: "slashing-protection-history",
	Usage:    "defines commands for interacting your validator's slashing protection history",
	Subcommands: []*cli.Command{
		{
			Name:        "export",
			Description: `exports your validator slashing protection history into an EIP-3076 compliant JSON`,
			Flags: cmd.WrapFlags([]cli.Flag{
				cmd.DataDirFlag,
				flags.SlashingProtectionExportDirFlag,
				features.Mainnet,
				features.PraterTestnet,
				features.RopstenTestnet,
				features.SepoliaTestnet,
				cmd.AcceptTosFlag,
			}),
			Before: func(cliCtx *cli.Context) error {
				if err := cmd.LoadFlagsFromConfig(cliCtx, cliCtx.Command.Flags); err != nil {
					return err
				}
				return tos.VerifyTosAcceptedOrPrompt(cliCtx)
			},
			Action: func(cliCtx *cli.Context) error {
				if err := features.ConfigureValidator(cliCtx); err != nil {
					return err
				}
				if err := exportSlashingProtectionJSON(cliCtx); err != nil {
					logrus.Fatalf("Could not export slashing protection file: %v", err)
				}
				return nil
			},
		},
		{
			Name:        "import",
			Description: `imports a selected EIP-3076 compliant slashing protection JSON to the validator database`,
			Flags: cmd.WrapFlags([]cli.Flag{
				cmd.DataDirFlag,
				flags.SlashingProtectionJSONFileFlag,
				features.Mainnet,
				features.PraterTestnet,
				features.RopstenTestnet,
				features.SepoliaTestnet,
				cmd.AcceptTosFlag,
			}),
			Before: func(cliCtx *cli.Context) error {
				if err := cmd.LoadFlagsFromConfig(cliCtx, cliCtx.Command.Flags); err != nil {
					return err
				}
				return tos.VerifyTosAcceptedOrPrompt(cliCtx)
			},
			Action: func(cliCtx *cli.Context) error {
				if err := features.ConfigureValidator(cliCtx); err != nil {
					return err
				}
				err := importSlashingProtectionJSON(cliCtx)
				if err != nil {
					logrus.Fatalf("Could not import slashing protection cli: %v", err)
				}
				return nil
			},
		},
	},
}
