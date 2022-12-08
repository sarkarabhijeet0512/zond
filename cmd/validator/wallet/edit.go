package wallet

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/theQRL/zond/validator/accounts"
	"github.com/theQRL/zond/validator/accounts/userprompt"
	"github.com/theQRL/zond/validator/accounts/wallet"
	"github.com/theQRL/zond/validator/keymanager"
	"github.com/theQRL/zond/validator/keymanager/remote"
	"github.com/urfave/cli/v2"
)

func remoteWalletEdit(c *cli.Context) error {
	w, err := wallet.OpenWalletOrElseCli(c, func(cliCtx *cli.Context) (*wallet.Wallet, error) {
		return nil, wallet.ErrNoWalletFound
	})
	if err != nil {
		return errors.Wrap(err, "could not open wallet")
	}
	if w.KeymanagerKind() != keymanager.Remote {
		return errors.New(
			fmt.Sprintf("Keymanager type: %s doesn't support configuration editing",
				w.KeymanagerKind().String()))
	}

	enc, err := w.ReadKeymanagerConfigFromDisk(c.Context)
	if err != nil {
		return errors.Wrap(err, "could not read config")
	}
	fileOpts, err := remote.UnmarshalOptionsFile(enc)
	if err != nil {
		return errors.Wrap(err, "could not unmarshal config")
	}
	log.Info("Current configuration")
	// Prints the current configuration to stdout.
	fmt.Println(fileOpts)
	newCfg, err := userprompt.InputRemoteKeymanagerConfig(c)
	if err != nil {
		return errors.Wrap(err, "could not get keymanager config")
	}

	opts := []accounts.Option{
		accounts.WithWallet(w),
		accounts.WithKeymanagerOpts(newCfg),
	}

	acc, err := accounts.NewCLIManager(opts...)
	if err != nil {
		return err
	}
	return acc.WalletEdit(c.Context)
}
