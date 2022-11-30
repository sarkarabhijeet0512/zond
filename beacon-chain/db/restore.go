package db

import (
	"os"
	"path"
	"strings"

	"github.com/pkg/errors"
	"github.com/theQRL/zond/beacon-chain/db/kv"
	"github.com/theQRL/zond/cmd"
	"github.com/theQRL/zond/io/file"
	"github.com/theQRL/zond/io/prompt"
	"github.com/urfave/cli/v2"
)

const dbExistsYesNoPrompt = "A database file already exists in the target directory. " +
	"Are you sure that you want to overwrite it? [y/n]"

// Restore a beacon chain database.
func Restore(cliCtx *cli.Context) error {
	sourceFile := cliCtx.String(cmd.RestoreSourceFileFlag.Name)
	targetDir := cliCtx.String(cmd.RestoreTargetDirFlag.Name)

	restoreDir := path.Join(targetDir, kv.BeaconNodeDbDirName)
	if file.FileExists(path.Join(restoreDir, kv.DatabaseFileName)) {
		resp, err := prompt.ValidatePrompt(
			os.Stdin, dbExistsYesNoPrompt, prompt.ValidateYesOrNo,
		)
		if err != nil {
			return errors.Wrap(err, "could not validate choice")
		}
		if strings.EqualFold(resp, "n") {
			log.Info("Restore aborted")
			return nil
		}
	}
	if err := file.MkdirAll(restoreDir); err != nil {
		return err
	}
	if err := file.CopyFile(sourceFile, path.Join(restoreDir, kv.DatabaseFileName)); err != nil {
		return err
	}

	log.Info("Restore completed successfully")
	return nil
}
