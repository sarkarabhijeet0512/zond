package remote_utils

import (
	"fmt"

	"github.com/logrusorgru/aurora"
	"github.com/theQRL/zond/validator/accounts/petnames"
)

// DisplayRemotePublicKeys prints remote public keys to stdout.
func DisplayRemotePublicKeys(validatingPubKeys [][1472]byte) {
	au := aurora.NewAurora(true)
	for i := 0; i < len(validatingPubKeys); i++ {
		fmt.Println("")
		fmt.Printf(
			"%s\n", au.BrightGreen(petnames.DeterministicName(validatingPubKeys[i][:], "-")).Bold(),
		)
		// Retrieve the validating key account metadata.
		fmt.Printf("%s %#x\n", au.BrightCyan("[validating public key]").Bold(), validatingPubKeys[i])
		fmt.Println(" ")
	}
}
