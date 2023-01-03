package p2p

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/multiformats/go-multiaddr"
	log "github.com/sirupsen/logrus"
	"github.com/theQRL/zond/beacon-chain/p2p/peers"
	"github.com/theQRL/zond/block"
	"github.com/theQRL/zond/chain"
	"github.com/theQRL/zond/common"
	"github.com/theQRL/zond/config"
	"github.com/theQRL/zond/metadata"
	"github.com/theQRL/zond/misc"
	"github.com/theQRL/zond/ntp"
	"github.com/theQRL/zond/p2p/messages"
	"github.com/theQRL/zond/p2p/znode"
	"github.com/theQRL/zond/protos"
	"github.com/theQRL/zond/transactions"
	"github.com/willf/bloom"
)

type connV1 struct {
	fd      network.Stream
	inbound bool
}

type peerDropV1 struct {
	*PeerV1
	err       error
	requested bool // true if signaled by the peer
}

type PeerIPWithPLData struct {
	multiAddr string
	PLData    *protos.PLData
}

type ServerV1 struct {
	config *config.Config

	host             host.Host
	chain            *chain.Chain
	ntp              ntp.NTPInterface
	peerData         *metadata.PeerData
	ipCount          map[string]int
	inboundCount     uint16
	totalConnections uint16
	peers            *peers.Status
	privateKey       *ecdsa.PrivateKey
	localnode        *znode.LocalNode

	listener     net.Listener
	lock         sync.Mutex
	peerInfoLock sync.Mutex

	running bool
	loopWG  sync.WaitGroup

	exit                        chan struct{}
	connectPeersExit            chan struct{}
	mrDataConn                  chan *MRDataConn
	addPeerToPeerList           chan *PeerIPWithPLData
	blockAndPeerChan            chan *BlockAndPeer
	addPeer                     chan *connV1
	delPeer                     chan *peerDropV1
	registerAndBroadcastChan    chan *messages.RegisterMessage
	blockReceivedForAttestation chan *block.Block
	attestationReceivedForBlock chan *transactions.Attest

	filter          *bloom.BloomFilter
	mr              *MessageReceiptV1
	downloader      *Downloader
	messagePriority map[protos.LegacyMessage_FuncName]uint64
}

func (srv *ServerV1) GetRegisterAndBroadcastChan() chan *messages.RegisterMessage {
	return srv.registerAndBroadcastChan
}

func (srv *ServerV1) GetBlockReceivedForAttestation() chan *block.Block {
	return srv.blockReceivedForAttestation
}

func (srv *ServerV1) GetAttestationReceivedForBlock() chan *transactions.Attest {
	return srv.attestationReceivedForBlock
}

func (srv *ServerV1) BroadcastBlock(block *block.Block) {
	blockHash := block.Hash()
	msg := &messages.RegisterMessage{
		Msg: &protos.LegacyMessage{
			FuncName: protos.LegacyMessage_BK,
			Data: &protos.LegacyMessage_Block{
				Block: block.PBData(),
			},
		},
		MsgHash: misc.BytesToHexStr(blockHash[:]),
	}
	srv.registerAndBroadcastChan <- msg
}

func (srv *ServerV1) BroadcastBlockForAttestation(block *block.Block, signature []byte) {
	partialBlockSigningHash := block.PartialBlockSigningHash()
	msg := &messages.RegisterMessage{
		Msg: &protos.LegacyMessage{
			FuncName: protos.LegacyMessage_BA,
			Data: &protos.LegacyMessage_BlockForAttestation{
				BlockForAttestation: &protos.BlockForAttestation{
					Block:     block.PBData(),
					Signature: signature,
				},
			},
		},
		MsgHash: misc.BytesToHexStr(partialBlockSigningHash[:]),
	}
	srv.registerAndBroadcastChan <- msg
}

func (srv *ServerV1) BroadcastAttestationTransaction(attestTx *transactions.Attest,
	slotNumber uint64, blockProposer []byte,
	parentHeaderHash common.Hash, partialBlockSigningHash common.Hash) {
	txHash := attestTx.TxHash(attestTx.GetSigningHash(partialBlockSigningHash))
	msg := &messages.RegisterMessage{
		Msg: &protos.LegacyMessage{
			FuncName: protos.LegacyMessage_AT,
			Data: &protos.LegacyMessage_AtData{
				AtData: &protos.ProtocolTransactionData{
					Tx:                      attestTx.PBData(),
					SlotNumber:              slotNumber,
					BlockProposer:           blockProposer,
					ParentHeaderHash:        parentHeaderHash[:],
					PartialBlockSigningHash: partialBlockSigningHash[:],
				},
			},
		},
		MsgHash: misc.BytesToHexStr(txHash[:]),
	}
	log.Info("[BroadcastAttestationTransaction] Broadcasting Attestation Txn ",
		msg.MsgHash)
	srv.registerAndBroadcastChan <- msg
}

func (srv *ServerV1) handleStream(s network.Stream) {

	log.Println("Got a new stream!")

	// Create a buffer stream for non blocking read and write.
	srv.addPeer <- &connV1{s, true}
}

func (srv *ServerV1) Start(keys crypto.PrivKey) (err error) {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if srv.running {
		return errors.New("server is already running")
	}

	srv.filter = bloom.New(200000, 5)
	//srv.chain.GetTransactionPool().SetRegisterAndBroadcastChan(srv.registerAndBroadcastChan)
	if err := srv.startListening(keys); err != nil {
		return err
	}

	srv.running = true
	go srv.run()
	go srv.downloader.DownloadMonitor()
	go srv.ConnectPeers()

	return nil
}

func (srv *ServerV1) Stop() (err error) {
	srv.lock.Lock()
	defer srv.lock.Unlock()

	if !srv.running {
		return
	}
	srv.running = false
	if srv.listener != nil {
		srv.listener.Close()
	}

	close(srv.exit)
	close(srv.connectPeersExit)
	srv.loopWG.Wait()

	return nil
}

func (srv *ServerV1) ConnectPeer(dest string) error {
	maddr, err := multiaddr.NewMultiaddr(dest)
	if err != nil {
		return err
	}

	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return err
	}

	// TODO: Look into PermanentAddrTTL
	srv.host.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)

	s, err := srv.host.NewStream(context.Background(),
		info.ID,
		config.GetDevConfig().ProtocolID)
	if err != nil {
		return err
	}

	srv.addPeer <- &connV1{s, false}

	return nil
}

func (srv *ServerV1) ConnectPeers() error {
	srv.loopWG.Add(1)
	defer srv.loopWG.Done()

	bootstrapPeers := make(map[string]bool)

	for _, multiAddr := range srv.config.User.Node.PeerList {
		//log.Info("Connecting peer ", peer)
		err := srv.peerData.AddDisconnectedPeers(multiAddr)
		if err != nil {
			log.Error("Failed to add bootstrap node in disconnected peers ", multiAddr,
				" Reason: ", err.Error())
			continue
		}
		bootstrapPeers[multiAddr] = true
	}

	peerList := make([]string, 0)
	for {
		select {
		case <-time.After(15 * time.Second):
			srv.peerInfoLock.Lock()
			if srv.inboundCount > srv.config.User.Node.MaxPeersLimit {
				srv.peerInfoLock.Unlock()
				break
			}

			maxConnectionTry := 10

			if len(peerList) == 0 {
				for _, p := range srv.peerData.DisconnectedPeers() {
					if connCount, ok := srv.ipCount[p.IP()]; ok {
						// Ignore skipping connection to addresses
						// when there is no connection with any peer
						if !(srv.totalConnections == 0 && connCount == 0) {
							continue
						}
					}
					peerList = append(peerList, p.MultiAddr())
				}
			}
			srv.peerInfoLock.Unlock()

			count := 0
			removePeers := make([]string, 0)
			for _, multiAddr := range peerList {
				if !srv.running {
					break
				}
				if count >= maxConnectionTry {
					break
				}
				log.Info("Trying to Connect ", multiAddr)
				err := srv.ConnectPeer(multiAddr)
				count += 1
				// Skip removal of bootstrapPeers
				if err != nil && !bootstrapPeers[multiAddr] {
					log.Info("Failed to connect to ", multiAddr)
					removePeers = append(removePeers, multiAddr)
					continue
				}
			}
			srv.peerInfoLock.Lock()
			for _, multiAddr := range removePeers {
				err := srv.peerData.RemovePeer(multiAddr)
				if err != nil {
					log.Error("Failed to removePeer",
						" Reason: ", err.Error())
					continue
				}
			}
			srv.peerInfoLock.Unlock()
			peerList = peerList[count:]

		case <-srv.connectPeersExit:
			return nil
		}
	}
}

func (srv *ServerV1) startListening(keys crypto.PrivKey) error {
	multiAddrStr := fmt.Sprintf("/ip4/%s/tcp/%d",
		srv.config.User.Node.BindingIP,
		srv.config.User.Node.LocalPort)
	sourceMultiAddr, _ := multiaddr.NewMultiaddr(multiAddrStr)

	host, err := libp2p.New(
		//context.Background(),
		libp2p.ListenAddrs(sourceMultiAddr),
		libp2p.Identity(keys),
	)
	if err != nil {
		return err
	}

	srv.host = host
	host.SetStreamHandler(config.GetDevConfig().ProtocolID,
		srv.handleStream)

	listenAddr := fmt.Sprintf("%s/p2p/%s",
		multiAddrStr, host.ID().Pretty())
	log.Info("Listening at ", listenAddr)

	//bindingAddress := fmt.Sprintf("%s:%d",
	//	srv.config.User.Node.BindingIP,
	//	srv.config.User.Node.LocalPort)

	//listener, err := net.Listen("tcp", bindingAddress)
	//if err != nil {
	//	return err
	//}
	//
	//srv.listener = listener
	//go srv.listenLoop(listener)

	return nil
}

func (srv *ServerV1) run() {
	var (
		peers = make(map[string]*PeerV1)
	)

	srv.loopWG.Add(1)
	defer srv.loopWG.Done()

running:
	for {
		select {
		case <-srv.exit:
			srv.downloader.Exit()
			log.Debug("Shutting Down ServerV1")
			break running
		case c := <-srv.addPeer:
			srv.peerInfoLock.Lock()
			log.Debug("Adding peer",
				" addr ", c.fd.Conn().RemoteMultiaddr())
			p := newPeerV1(
				c.fd,
				c.inbound,
				srv.chain,
				srv.filter,
				srv.mr,
				srv.peerData,
				srv.mrDataConn,
				srv.registerAndBroadcastChan,
				srv.blockReceivedForAttestation,
				srv.attestationReceivedForBlock,
				srv.addPeerToPeerList,
				srv.blockAndPeerChan,
				srv.messagePriority)
			go srv.runPeer(p)
			peers[c.fd.ID()] = p

			ip := misc.IPFromMultiAddr(c.fd.Conn().RemoteMultiaddr().String())

			srv.ipCount[ip] += 1
			srv.totalConnections += 1
			if p.inbound {
				srv.inboundCount++
			}

			if srv.ipCount[ip] > srv.config.User.Node.MaxRedundantConnections {
				log.Info("Disconnecting due to max redundant connections")
				p.Disconnect()
				// TODO: Ban peer
			}

			srv.peerInfoLock.Unlock()
			srv.downloader.AddPeer(p)

		case pd := <-srv.delPeer:
			srv.peerInfoLock.Lock()

			log.Debug("Removing Peer", "err", pd.err)
			peer := peers[pd.stream.ID()]
			delete(peers, pd.stream.ID())
			if pd.inbound {
				srv.inboundCount--
			}
			ip := pd.ip

			srv.ipCount[ip] -= 1
			srv.totalConnections -= 1
			if pd.isPLShared {
				err := srv.peerData.AddDisconnectedPeers(pd.multiAddr)
				if err != nil {
					log.Error("Failed to add peer into disconnected peers",
						" ", pd.multiAddr,
						" Reason: ", err.Error())
				}
			}
			srv.peerInfoLock.Unlock()

			srv.downloader.RemovePeer(peer)

		case mrDataConn := <-srv.mrDataConn:
			// TODO: Process Message Receipt
			// Need to get connection too
			mrData := mrDataConn.mrData
			msgHash := misc.BytesToHexStr(mrData.Hash)
			switch mrData.Type {
			case protos.LegacyMessage_BA:
				/*
					1. Verify if Block Received for attestation is valid
					2. Broadcast the block
					3. Attest the block if Staking is Enabled on this node
				*/
				var parentHash common.Hash
				copy(parentHash[:], mrData.ParentHeaderHash)

				_, err := srv.chain.GetBlock(parentHash)
				if err != nil {
					log.Info("[BlockForAttestation] Missing Parent Block",
						" #", mrData.SlotNumber,
						" Partial Block Signing Hash ", misc.BytesToHexStr(mrData.Hash),
						" Parent Block ", misc.BytesToHexStr(mrData.ParentHeaderHash))
					break
				}

				if srv.mr.contains(mrData.Hash, mrData.Type) {
					break
				}

				srv.mr.addPeer(mrData, mrDataConn.peer)

				value, ok := srv.mr.GetRequestedHash(msgHash)
				if ok && value.GetRequested() {
					break
				}

				go srv.RequestFullMessage(mrData)

				//TODO: Logic to be written
				//srv.blockReceivedForAttestation
			case protos.LegacyMessage_BK:
				finalizedHeaderHash, err := srv.chain.GetFinalizedHeaderHash()
				if err != nil {
					log.Error("No Finalized Header Hash ", err)
				}
				if (finalizedHeaderHash != common.Hash{}) {
					finalizedBlock, err := srv.chain.GetBlock(finalizedHeaderHash)
					if err != nil {
						log.Error("Failed to get finalized block ",
							misc.BytesToHexStr(finalizedHeaderHash[:]))
						break
					}
					// skip slot number beyond the Finalized slot Number
					if finalizedBlock.SlotNumber() >= mrData.SlotNumber {
						log.Warn("[BlockReceived] Block #", mrData.SlotNumber,
							" is beyond finalized block #", finalizedBlock.SlotNumber())
						break
					}
				}

				var parentHash common.Hash
				copy(parentHash[:], mrData.ParentHeaderHash)

				_, err = srv.chain.GetBlock(parentHash)
				if err != nil {
					log.Info("[BlockReceived] Missing Parent Block ",
						" #", mrData.SlotNumber,
						" Block ", misc.BytesToHexStr(mrData.Hash),
						" Parent Block ", misc.BytesToHexStr(mrData.ParentHeaderHash))
					break
				}

				if srv.mr.contains(mrData.Hash, mrData.Type) {
					break
				}

				srv.mr.addPeer(mrData, mrDataConn.peer)

				value, ok := srv.mr.GetRequestedHash(msgHash)
				if ok && value.GetRequested() {
					break
				}

				go srv.RequestFullMessage(mrData)
				// Request for full message
				// Check if its already being feeded by any other peer
			case protos.LegacyMessage_TT:
				srv.HandleTransaction(mrDataConn)
			case protos.LegacyMessage_ST:
				srv.HandleTransaction(mrDataConn)
			case protos.LegacyMessage_AT:
				srv.HandleTransaction(mrDataConn)
			default:
				log.Warn("Unknown Message Receipt Type",
					"Type", mrData.Type)
				mrDataConn.peer.Disconnect()
			}
		case blockAndPeer := <-srv.blockAndPeerChan:
			srv.BlockReceived(blockAndPeer.peer, blockAndPeer.block)
		case addPeerToPeerList := <-srv.addPeerToPeerList:
			srv.UpdatePeerList(addPeerToPeerList)
		case registerAndBroadcast := <-srv.registerAndBroadcastChan:
			srv.mr.Register(registerAndBroadcast.MsgHash, registerAndBroadcast.Msg)
			binMsgHash, err := misc.HexStrToBytes(registerAndBroadcast.MsgHash)
			if err != nil {
				log.Error("Error decoding message hash ", err.Error())
				continue
			}
			out := &MsgV1{
				msg: &protos.LegacyMessage{
					FuncName: protos.LegacyMessage_MR,
					Data: &protos.LegacyMessage_MrData{
						MrData: &protos.MRData{
							Hash: binMsgHash,
							Type: registerAndBroadcast.Msg.FuncName,
						},
					},
				},
			}
			b := registerAndBroadcast.Msg.GetBlock()
			if b != nil {
				out.msg.GetMrData().SlotNumber = b.Header.SlotNumber
				out.msg.GetMrData().ParentHeaderHash = b.Header.ParentHash
			} else {
				ba := registerAndBroadcast.Msg.GetBlockForAttestation()
				if ba != nil {
					out.msg.GetMrData().SlotNumber = ba.Block.Header.SlotNumber
					out.msg.GetMrData().ParentHeaderHash = ba.Block.Header.ParentHash
				}
			}
			ignorePeers := make(map[*PeerV1]bool, 0)
			if msgRequest, ok := srv.mr.GetRequestedHash(registerAndBroadcast.MsgHash); ok {
				ignorePeers = msgRequest.peers
			}
			for _, p := range peers {
				if _, ok := ignorePeers[p]; !ok {
					p.Send(out)
				}
			}
		}
	}
	for _, p := range peers {
		p.Disconnect()
	}
}

func (srv *ServerV1) HandleTransaction(mrDataConn *MRDataConn) {
	mrData := mrDataConn.mrData
	srv.mr.addPeer(mrData, mrDataConn.peer)

	// TODO: Ignore transaction if node is syncing
	if srv.downloader.isSyncing {
		return
	}
	if srv.chain.GetTransactionPool().IsFull() {
		return
	}
	go srv.RequestFullMessage(mrData)
}

func (srv *ServerV1) RequestFullMessage(mrData *protos.MRData) {
	for {
		msgHash := misc.BytesToHexStr(mrData.Hash)
		_, ok := srv.mr.GetHashMsg(msgHash)
		if ok {
			if _, ok = srv.mr.GetRequestedHash(msgHash); ok {
				srv.mr.RemoveRequestedHash(msgHash)
			}
			return
		}
		requestedHash, ok := srv.mr.GetRequestedHash(msgHash)
		if !ok {
			return
		}
		peer := requestedHash.GetPeer()
		if peer == nil {
			return
		}
		requestedHash.SetPeer(peer, true)
		mrData := &protos.MRData{
			Hash: mrData.Hash,
			Type: mrData.Type,
		}
		out := &MsgV1{}
		out.msg = &protos.LegacyMessage{
			FuncName: protos.LegacyMessage_SFM,
			Data: &protos.LegacyMessage_MrData{
				MrData: mrData,
			},
		}
		peer.Send(out)

		time.Sleep(time.Duration(srv.config.Dev.MessageReceiptTimeout) * time.Second)
	}
}

func (srv *ServerV1) BlockReceived(peer *PeerV1, b *block.Block) {
	blockHash := b.Hash()
	headerHash := misc.BytesToHexStr(blockHash[:])
	log.Info(">>> Received Block",
		" #", b.SlotNumber(),
		" Hash ", headerHash)

	// TODO: Trigger Syncing/Block downloader
	select {
	case srv.downloader.blockAndPeerChannel <- &BlockAndPeer{b, peer}:
	case <-time.After(5 * time.Second):
		log.Info("Timeout for Received Block",
			"#", b.SlotNumber(),
			"Hash", headerHash)
	}
}

func (srv *ServerV1) UpdatePeerList(p *PeerIPWithPLData) error {
	err := srv.peerData.AddConnectedPeers(p.multiAddr)
	if err != nil {
		log.Error("Failed to Add Peer into peer list",
			" ", p.multiAddr,
			" Reason: ", err.Error())
		return err
	}
	for _, peerMultiAddr := range p.PLData.PeerIps {
		if srv.peerData.IsPeerInList(peerMultiAddr) {
			continue
		}
		err = srv.peerData.AddDisconnectedPeers(peerMultiAddr)
		if err != nil {
			log.Error("Failed to add peer ", peerMultiAddr, " in peer list",
				" Reason: ", err.Error())
			continue
		}
	}
	return nil
}

func (srv *ServerV1) runPeer(p *PeerV1) {
	remoteRequested := p.run()

	srv.delPeer <- &peerDropV1{p, nil, remoteRequested}
}

func NewServer(chain *chain.Chain) (*ServerV1, error) {
	peerData, err := metadata.NewPeerData()
	if err != nil {
		return nil, err
	}
	srv := &ServerV1{
		config:     config.GetConfig(),
		chain:      chain,
		ntp:        ntp.GetNTP(),
		peerData:   peerData,
		ipCount:    make(map[string]int),
		mr:         CreateMRV1(),
		downloader: NewDownloader(chain),

		exit:                        make(chan struct{}),
		connectPeersExit:            make(chan struct{}),
		mrDataConn:                  make(chan *MRDataConn),
		addPeerToPeerList:           make(chan *PeerIPWithPLData),
		blockAndPeerChan:            make(chan *BlockAndPeer),
		addPeer:                     make(chan *connV1),
		delPeer:                     make(chan *peerDropV1),
		registerAndBroadcastChan:    make(chan *messages.RegisterMessage, 100),
		blockReceivedForAttestation: make(chan *block.Block),
		attestationReceivedForBlock: make(chan *transactions.Attest),

		messagePriority: make(map[protos.LegacyMessage_FuncName]uint64),
	}

	srv.messagePriority[protos.LegacyMessage_VE] = 0
	srv.messagePriority[protos.LegacyMessage_PL] = 0
	srv.messagePriority[protos.LegacyMessage_PONG] = 0

	srv.messagePriority[protos.LegacyMessage_MR] = 2
	srv.messagePriority[protos.LegacyMessage_SFM] = 1

	srv.messagePriority[protos.LegacyMessage_BA] = 1
	srv.messagePriority[protos.LegacyMessage_BK] = 1
	srv.messagePriority[protos.LegacyMessage_FB] = 0
	srv.messagePriority[protos.LegacyMessage_PB] = 0

	srv.messagePriority[protos.LegacyMessage_TT] = 1
	srv.messagePriority[protos.LegacyMessage_ST] = 1
	srv.messagePriority[protos.LegacyMessage_AT] = 1

	srv.messagePriority[protos.LegacyMessage_SYNC] = 0
	srv.messagePriority[protos.LegacyMessage_CHAINSTATE] = 0
	srv.messagePriority[protos.LegacyMessage_EBHREQ] = 0
	srv.messagePriority[protos.LegacyMessage_EBHRESP] = 0
	srv.messagePriority[protos.LegacyMessage_P2P_ACK] = 0

	return srv, nil
}
func (srv *ServerV1) NodeInfo() *NodeInfoV1 {
	// Gather and assemble the generic node infos
	node := srv.Self()
	info := &NodeInfoV1{
		// Name:       srv.Name,
		Znode: node.URLv4(),
		ID:    node.ID().String(),
		IP:    node.IP().String(),
		// ListenAddr: srv.ListenAddr,
		Protocols: make(map[string]interface{}),
	}
	info.Ports.Discovery = node.UDP()
	info.Ports.Listener = node.TCP()
	info.ZNR = node.String()

	// Gather all the running protocol infos (only once per protocol type)
	// for _, proto := range srv.Protocols {
	// 	if _, ok := info.Protocols[proto.Name]; !ok {
	// 		nodeInfo := interface{}("unknown")
	// 		if query := proto.NodeInfo; query != nil {
	// 			nodeInfo = proto.NodeInfo()
	// 		}
	// 		info.Protocols[proto.Name] = nodeInfo
	// 	}
	// }
	return info
}

type NodeInfoV1 struct {
	ID    string `json:"id"`    // Unique node identifier (also the encryption key)
	Name  string `json:"name"`  // Name of the node, including client type, version, OS, custom data
	Znode string `json:"znode"` // Znode URL for adding this peer from remote peers
	ZNR   string `json:"znr"`   // Ethereum Node Record
	IP    string `json:"ip"`    // IP address of the node
	Ports struct {
		Discovery int `json:"discovery"` // UDP listening port for discovery protocol
		Listener  int `json:"listener"`  // TCP listening port for RLPx
	} `json:"ports"`
	ListenAddr string                 `json:"listenAddr"`
	Protocols  map[string]interface{} `json:"protocols"`
}

// Self returns the local node's endpoint information.
func (srv *ServerV1) Self() *znode.Node {
	srv.lock.Lock()
	ln := srv.localnode
	srv.lock.Unlock()

	if ln == nil {
		// return znode.NewV4(&srv.PrivateKey.PublicKey, net.ParseIP("0.0.0.0"), 0, 0)
	}
	return ln.Node()
}
