package p2p

import (
	"crypto/ecdsa"
	"fmt"
	"net"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/theQRL/zond/crypto"
	"github.com/theQRL/zond/p2p/discover"
	"github.com/theQRL/zond/p2p/znode"
	"github.com/theQRL/zond/p2p/znr"
)

const (
	// Limit for rate limiter when processing new inbound dials.
	ipLimit = 4

	// Burst limit for inbound dials.
	ipBurst = 8

	// High watermark buffer signifies the buffer till which
	// we will handle inbound requests.
	highWatermarkBuffer = 10
)

// Listener defines the discovery V5 network interface that is used
// to communicate with other peers.
type Listener interface {
	Self() *znode.Node
	Close()
	Lookup(znode.ID) []*znode.Node
	Resolve(*znode.Node) *znode.Node
	RandomNodes() znode.Iterator
	Ping(*znode.Node) error
	RequestZNR(*znode.Node) (*znode.Node, error)
	LocalNode() *znode.LocalNode
}

// listen for new nodes watches for new nodes in the network and adds them to the peerstore.
func (s *Server) listenForNewNodes() {
	iterator := s.dv5Listener.RandomNodes()
	iterator = znode.Filter(iterator, s.filterPeer)
	defer iterator.Close()
	for {
		// Exit if service's context is canceled
		if s.ctx.Err() != nil {
			break
		}
		if s.isPeerAtLimit(false /* inbound */) {
			// Pause the main loop for a period to stop looking
			// for new peers.
			log.Trace("Not looking for peers, at peer limit")
			time.Sleep(pollingPeriod)
			continue
		}
		exists := iterator.Next()
		if !exists {
			break
		}
		node := iterator.Node()
		peerInfo, _, err := convertToAddrInfo(node)
		if err != nil {
			log.WithError(err).Error("Could not convert to peer info")
			continue
		}
		// Make sure that peer is not dialed too often, for each connection attempt there's a backoff period.
		s.Peers().RandomizeBackOff(peerInfo.ID)
		go func(info *peer.AddrInfo) {
			if err := s.connectWithPeer(s.ctx, *info); err != nil {
				log.WithError(err).Tracef("Could not connect with peer %s", info.String())
			}
		}(peerInfo)
	}
}

func (s *Server) createListener(
	ipAddr net.IP,
	privKey *ecdsa.PrivateKey,
) (*discover.UDPv5, error) {
	// BindIP is used to specify the ip
	// on which we will bind our listener on
	// by default we will listen to all interfaces.
	var bindIP net.IP
	switch udpVersionFromIP(ipAddr) {
	case "udp4":
		bindIP = net.IPv4zero
	case "udp6":
		bindIP = net.IPv6zero
	default:
		return nil, errors.New("invalid ip provided")
	}

	// If local ip is specified then use that instead.
	if s.config.User.Node.BindingIP != "" {
		ipAddr = net.ParseIP(s.config.User.Node.BindingIP)
		if ipAddr == nil {
			return nil, errors.New("invalid local ip provided")
		}
		bindIP = ipAddr
	}
	udpAddr := &net.UDPAddr{
		IP:   bindIP,
		Port: int(s.config.User.Node.UDPPort),
	}
	// Listen to all network interfaces
	// for both ip protocols.
	networkVersion := "udp"
	conn, err := net.ListenUDP(networkVersion, udpAddr)
	if err != nil {
		return nil, errors.Wrap(err, "could not listen to UDP")
	}

	localNode, err := s.createLocalNode(
		privKey,
		ipAddr,
		int(s.config.User.Node.UDPPort),
		int(s.config.User.Node.PublicPort),
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not create local node")
	}
	if s.config.User.Node.HostAddress != "" {
		hostIP := net.ParseIP(s.config.User.Node.HostAddress)
		if hostIP.To4() == nil && hostIP.To16() == nil {
			log.Errorf("Invalid host address given: %s", hostIP.String())
		} else {
			localNode.SetFallbackIP(hostIP)
			localNode.SetStaticIP(hostIP)
		}
	}
	if s.config.User.Node.HostDNS != "" {
		host := s.config.User.Node.HostDNS
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, errors.Wrap(err, "could not resolve host address")
		}
		if len(ips) > 0 {
			// Use first IP returned from the
			// resolver.
			firstIP := ips[0]
			localNode.SetFallbackIP(firstIP)
		}
	}
	dv5Cfg := discover.Config{
		PrivateKey: privKey,
	}
	dv5Cfg.Bootnodes = []*znode.Node{}
	for _, addr := range s.config.Dev.Discv5BootStrapAddr {
		bootNode, err := znode.Parse(znode.ValidSchemes, addr)
		if err != nil {
			return nil, errors.Wrap(err, "could not bootstrap addr")
		}
		dv5Cfg.Bootnodes = append(dv5Cfg.Bootnodes, bootNode)
	}

	listener, err := discover.ListenV5(conn, localNode, dv5Cfg)
	if err != nil {
		return nil, errors.Wrap(err, "could not listen to discV5")
	}
	return listener, nil
}

func (s *Server) createLocalNode(
	privKey *ecdsa.PrivateKey,
	ipAddr net.IP,
	udpPort, tcpPort int,
) (*znode.LocalNode, error) {
	db, err := znode.OpenDB("")
	if err != nil {
		return nil, errors.Wrap(err, "could not open node's peer database")
	}
	localNode := znode.NewLocalNode(db, privKey)

	ipEntry := znr.IP(ipAddr)
	udpEntry := znr.UDP(udpPort)
	tcpEntry := znr.TCP(tcpPort)
	localNode.Set(ipEntry)
	localNode.Set(udpEntry)
	localNode.Set(tcpEntry)
	localNode.SetFallbackIP(ipAddr)
	localNode.SetFallbackUDP(udpPort)

	// localNode, err = addForkEntry(localNode, s.genesisTime, s.genesisValidatorsRoot)
	// if err != nil {
	// 	return nil, errors.Wrap(err, "could not add eth2 fork version entry to znr")
	// }
	// localNode = initializeAttSubnets(localNode)
	// return initializeSyncCommSubnets(localNode), nil
	return localNode, nil
}

func (s *Server) startDiscoveryV5(
	addr net.IP,
	privKey *ecdsa.PrivateKey,
) (*discover.UDPv5, error) {
	listener, err := s.createListener(addr, privKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not create listener")
	}
	record := listener.Self()
	log.WithField("ZNR", record.String()).Info("Started discovery v5")
	return listener, nil
}

// filterPeer validates each node that we retrieve from our dht. We
// try to ascertain that the peer can be a valid protocol peer.
// Validity Conditions:
//  1. The local node is still actively looking for peers to
//     connect to.
//  2. Peer has a valid IP and TCP port set in their znr.
//  3. Peer hasn't been marked as 'bad'
//  4. Peer is not currently active or connected.
//  5. Peer is ready to receive incoming connections.
//  6. Peer's fork digest in their ZNR matches that of
//     our localnodes.
func (s *Server) filterPeer(node *znode.Node) bool {
	// Ignore nil node entries passed in.
	if node == nil {
		return false
	}
	// ignore nodes with no ip address stored.
	if node.IP() == nil {
		return false
	}
	// do not dial nodes with their tcp ports not set
	if err := node.Record().Load(znr.WithEntry("tcp", new(znr.TCP))); err != nil {
		if !znr.IsNotFound(err) {
			log.WithError(err).Debug("Could not retrieve tcp port")
		}
		return false
	}
	peerData, multiAddr, err := convertToAddrInfo(node)
	if err != nil {
		log.WithError(err).Debug("Could not convert to peer data")
		return false
	}
	if s.peers.IsBad(peerData.ID) {
		return false
	}
	if s.peers.IsActive(peerData.ID) {
		return false
	}
	if s.host.Network().Connectedness(peerData.ID) == network.Connected {
		return false
	}
	if !s.peers.IsReadyToDial(peerData.ID) {
		return false
	}
	nodeZNR := node.Record()
	// Decide whether or not to connect to peer that does not
	// match the proper fork ZNR data with our local node.
	// if s.genesisValidatorsRoot != nil {
	// 	if err := s.compareForkENR(nodeENR); err != nil {
	// 		log.WithError(err).Trace("Fork ZNR mismatches between peer and local node")
	// 		return false
	// 	}
	// }
	// Add peer to peer handler.
	s.peers.Add(nodeZNR, peerData.ID, multiAddr, network.DirUnknown)
	return true
}

func convertToAddrInfo(node *znode.Node) (*peer.AddrInfo, ma.Multiaddr, error) {
	multiAddr, err := convertToSingleMultiAddr(node)
	if err != nil {
		return nil, nil, err
	}
	info, err := peer.AddrInfoFromP2pAddr(multiAddr)
	if err != nil {
		return nil, nil, err
	}
	return info, multiAddr, nil
}

func multiAddressBuilderWithID(ipAddr, protocol string, port uint, id peer.ID) (ma.Multiaddr, error) {
	parsedIP := net.ParseIP(ipAddr)
	if parsedIP.To4() == nil && parsedIP.To16() == nil {
		return nil, errors.Errorf("invalid ip address provided: %s", ipAddr)
	}
	if id.String() == "" {
		return nil, errors.New("empty peer id given")
	}
	if parsedIP.To4() != nil {
		return ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/%s/%d/p2p/%s", ipAddr, protocol, port, id.String()))
	}
	return ma.NewMultiaddr(fmt.Sprintf("/ip6/%s/%s/%d/p2p/%s", ipAddr, protocol, port, id.String()))
}

func convertToMultiAddr(nodes []*znode.Node) []ma.Multiaddr {
	var multiAddrs []ma.Multiaddr
	for _, node := range nodes {
		// ignore nodes with no ip address stored
		if node.IP() == nil {
			continue
		}
		multiAddr, err := convertToSingleMultiAddr(node)
		if err != nil {
			log.WithError(err).Error("Could not convert to multiAddr")
			continue
		}
		multiAddrs = append(multiAddrs, multiAddr)
	}
	return multiAddrs
}

func convertToSingleMultiAddr(node *znode.Node) (ma.Multiaddr, error) {
	pubkey := node.Pubkey()
	assertedKey, err := crypto.ConvertToInterfacePubkey(pubkey)
	if err != nil {
		return nil, errors.Wrap(err, "could not get pubkey")
	}
	id, err := peer.IDFromPublicKey(assertedKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not get peer id")
	}
	return multiAddressBuilderWithID(node.IP().String(), "tcp", uint(node.TCP()), id)
}

// This checks our set max peers in our config, and
// determines whether our currently connected and
// active peers are above our set max peer limit.
func (s *Server) isPeerAtLimit(inbound bool) bool {
	numOfConns := len(s.host.Network().Peers())
	maxPeers := int(s.config.User.Node.MaxPeersLimit)
	// If we are measuring the limit for inbound peers
	// we apply the high watermark buffer.
	if inbound {
		maxPeers += highWatermarkBuffer
		maxInbound := s.peers.InboundLimit() + highWatermarkBuffer
		currInbound := len(s.peers.InboundConnected())
		// Exit early if we are at the inbound limit.
		if currInbound >= maxInbound {
			return true
		}
	}
	activePeers := len(s.Peers().Active())
	return activePeers >= maxPeers || numOfConns >= maxPeers
}

func udpVersionFromIP(ipAddr net.IP) string {
	if ipAddr.To4() != nil {
		return "udp4"
	}
	return "udp6"
}
