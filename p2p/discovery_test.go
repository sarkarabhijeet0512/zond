package p2p

import (
	"crypto/ecdsa"
	"math/rand"
	"net"
	"os"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theQRL/zond/config"
	"github.com/theQRL/zond/crypto"
	"github.com/theQRL/zond/p2p/discover"
)

var discoveryWaitTime = 1 * time.Second

func TestStartDiscV5_DiscoverAllPeers(t *testing.T) {
	port := 2000
	ipAddr, pkey := createAddrAndPrivKey(t)

	s := &Server{
		config: &config.Config{
			User: &config.UserConfig{Node: &config.NodeConfig{UDPPort: uint16(port)}, NodeKeyFileName: ""},
			Dev:  &config.DevConfig{Discv5BootStrapAddr: []string{}},
		},
	}
	bootListener, err := s.createListener(ipAddr, pkey)
	require.NoError(t, err)
	defer bootListener.Close()

	bootNode := bootListener.Self()

	var listeners []*discover.UDPv5
	for i := 1; i <= 5; i++ {
		port = 3000 + i
		cfg := &config.Config{
			Dev:  &config.DevConfig{Discv5BootStrapAddr: []string{bootNode.String()}},
			User: &config.UserConfig{Node: &config.NodeConfig{UDPPort: uint16(port)}, NodeKeyFileName: ""},
		}

		ipAddr, pkey := createAddrAndPrivKey(t)
		s = &Server{
			config: cfg,
		}
		listener, err := s.startDiscoveryV5(ipAddr, pkey)
		assert.NoError(t, err, "Could not start discovery for node")
		listeners = append(listeners, listener)
	}
	defer func() {
		// Close down all peers.
		for _, listener := range listeners {
			listener.Close()
		}
	}()

	// Wait for the nodes to have their local routing tables to be populated with the other nodes
	time.Sleep(discoveryWaitTime)

	lastListener := listeners[len(listeners)-1]
	nodes := lastListener.Lookup(bootNode.ID())
	if len(nodes) < 4 {
		t.Errorf("The node's local table doesn't have the expected number of nodes. "+
			"Expected more than or equal to %d but got %d", 4, len(nodes))
	}
}

func createAddrAndPrivKey(t *testing.T) (net.IP, *ecdsa.PrivateKey) {
	ip := "127.0.0.1"
	ipAddr := net.ParseIP(ip)
	temp := t.TempDir()
	randNum := rand.Int()
	tempPath := path.Join(temp, strconv.Itoa(randNum))
	require.NoError(t, os.Mkdir(tempPath, 0700))
	pkey, err := crypto.PrivKey(&config.Config{User: &config.UserConfig{BaseDir: tempPath}})
	require.NoError(t, err, "Could not get private key")
	return ipAddr, pkey
}
