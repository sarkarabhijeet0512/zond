package discover

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	crypto2 "github.com/theQRL/go-libp2p-qrl/crypto"
	"github.com/theQRL/zond/common/mclock"
	"github.com/theQRL/zond/log"
	"github.com/theQRL/zond/p2p/discover/v5wire"
	"github.com/theQRL/zond/p2p/netutil"
	"github.com/theQRL/zond/p2p/znode"
	"github.com/theQRL/zond/p2p/znr"
)

// UDPConn is a network connection on which discovery can operate.
type UDPConn interface {
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error)
	Close() error
	LocalAddr() net.Addr
}

const (
	respTimeout    = 500 * time.Millisecond
	expiration     = 20 * time.Second
	bondExpiration = 24 * time.Hour

	ntpFailureThreshold = 32               // Continuous timeouts after which to check NTP
	ntpWarningCooldown  = 10 * time.Minute // Minimum amount of time to pass before repeating NTP warning
	driftThreshold      = 10 * time.Second // Allowed clock drift before warning user

	// Discovery packets are defined to be no larger than 1280 bytes.
	// Packets larger than this size will be cut at the end and treated
	// as invalid because their hash won't match.
	maxPacketSize = 1280
)

// Config holds settings for the discovery listener.
type Config struct {
	// These settings are required and configure the UDP listener:
	// PrivateKey *ecdsa.PrivateKey
	PrivateKey *crypto2.DilithiumPrivateKey

	// These settings are optional:
	NetRestrict  *netutil.Netlist   // list of allowed IP networks
	Bootnodes    []*znode.Node      // list of bootstrap nodes
	Unhandled    chan<- ReadPacket  // unhandled packets are sent on this channel
	Log          log.Logger         // if set, log messages go here
	ValidSchemes znr.IdentityScheme // allowed identity schemes
	Clock        mclock.Clock
}

func (cfg Config) withDefaults() Config {
	if cfg.Log == nil {
		cfg.Log = log.Root()
	}
	if cfg.ValidSchemes == nil {
		cfg.ValidSchemes = znode.ValidSchemes
	}
	if cfg.Clock == nil {
		cfg.Clock = mclock.System{}
	}
	return cfg
}

// ReadPacket is a packet that couldn't be handled. Those packets are sent to the unhandled
// channel if configured.
type ReadPacket struct {
	Data []byte
	Addr *net.UDPAddr
}

func min(x, y int) int {
	if x > y {
		return y
	}
	return x
}

const (
	lookupRequestLimit      = 3  // max requests against a single node during lookup
	findnodeResultLimit     = 16 // applies in FINDNODE handler
	totalNodesResponseLimit = 5  // applies in waitForNodes
	nodesResponseItemLimit  = 3  // applies in sendNodes

	respTimeoutV5 = 700 * time.Millisecond
)

// codecV5 is implemented by v5wire.Codec (and testCodec).
//
// The UDPv5 transport is split into two objects: the codec object deals with
// encoding/decoding and with the handshake; the UDPv5 object handles higher-level concerns.
type codecV5 interface {
	// Encode encodes a packet.
	Encode(znode.ID, string, v5wire.Packet, *v5wire.Whoareyou) ([]byte, v5wire.Nonce, error)

	// decode decodes a packet. It returns a *v5wire.Unknown packet if decryption fails.
	// The *znode.Node return value is non-nil when the input contains a handshake response.
	Decode([]byte, string) (znode.ID, *znode.Node, v5wire.Packet, error)
}

// UDPv5 is the implementation of protocol version 5.
type UDPv5 struct {
	// static fields
	conn        UDPConn
	tab         *Table
	netrestrict *netutil.Netlist
	// priv         *ecdsa.PrivateKey
	priv         *crypto2.DilithiumPrivateKey
	localNode    *znode.LocalNode
	db           *znode.DB
	log          log.Logger
	clock        mclock.Clock
	validSchemes znr.IdentityScheme

	// talkreq handler registry
	trlock     sync.Mutex
	trhandlers map[string]TalkRequestHandler

	// channels into dispatch
	packetInCh    chan ReadPacket
	readNextCh    chan struct{}
	callCh        chan *callV5
	callDoneCh    chan *callV5
	respTimeoutCh chan *callTimeout

	// state of dispatch
	codec            codecV5
	activeCallByNode map[znode.ID]*callV5
	activeCallByAuth map[v5wire.Nonce]*callV5
	callQueue        map[znode.ID][]*callV5

	// shutdown stuff
	closeOnce      sync.Once
	closeCtx       context.Context
	cancelCloseCtx context.CancelFunc
	wg             sync.WaitGroup
}

// TalkRequestHandler callback processes a talk request and optionally returns a reply
type TalkRequestHandler func(znode.ID, *net.UDPAddr, []byte) []byte

// callV5 represents a remote procedure call against another node.
type callV5 struct {
	node         *znode.Node
	packet       v5wire.Packet
	responseType byte // expected packet type of response
	reqid        []byte
	ch           chan v5wire.Packet // responses sent here
	err          chan error         // errors sent here

	// Valid for active calls only:
	nonce          v5wire.Nonce      // nonce of request packet
	handshakeCount int               // # times we attempted handshake for this call
	challenge      *v5wire.Whoareyou // last sent handshake challenge
	timeout        mclock.Timer
}

// callTimeout is the response timeout event of a call.
type callTimeout struct {
	c     *callV5
	timer mclock.Timer
}

// ListenV5 listens on the given connection.
func ListenV5(conn UDPConn, ln *znode.LocalNode, cfg Config) (*UDPv5, error) {
	t, err := newUDPv5(conn, ln, cfg)
	if err != nil {
		return nil, err
	}
	go t.tab.loop()
	t.wg.Add(2)
	go t.readLoop()
	go t.dispatch()
	return t, nil
}

// newUDPv5 creates a UDPv5 transport, but doesn't start any goroutines.
func newUDPv5(conn UDPConn, ln *znode.LocalNode, cfg Config) (*UDPv5, error) {
	closeCtx, cancelCloseCtx := context.WithCancel(context.Background())
	cfg = cfg.withDefaults()
	t := &UDPv5{
		// static fields
		conn:         conn,
		localNode:    ln,
		db:           ln.Database(),
		netrestrict:  cfg.NetRestrict,
		priv:         cfg.PrivateKey,
		log:          cfg.Log,
		validSchemes: cfg.ValidSchemes,
		clock:        cfg.Clock,
		trhandlers:   make(map[string]TalkRequestHandler),
		// channels into dispatch
		packetInCh:    make(chan ReadPacket, 1),
		readNextCh:    make(chan struct{}, 1),
		callCh:        make(chan *callV5),
		callDoneCh:    make(chan *callV5),
		respTimeoutCh: make(chan *callTimeout),
		// state of dispatch
		codec:            v5wire.NewCodec(ln, cfg.PrivateKey, cfg.Clock),
		activeCallByNode: make(map[znode.ID]*callV5),
		activeCallByAuth: make(map[v5wire.Nonce]*callV5),
		callQueue:        make(map[znode.ID][]*callV5),
		// shutdown
		closeCtx:       closeCtx,
		cancelCloseCtx: cancelCloseCtx,
	}
	tab, err := newTable(t, t.db, cfg.Bootnodes, cfg.Log)
	if err != nil {
		return nil, err
	}
	t.tab = tab
	return t, nil
}

// Self returns the local node record.
func (t *UDPv5) Self() *znode.Node {
	return t.localNode.Node()
}

// Close shuts down packet processing.
func (t *UDPv5) Close() {
	t.closeOnce.Do(func() {
		t.cancelCloseCtx()
		t.conn.Close()
		t.wg.Wait()
		t.tab.close()
	})
}

// Ping sends a ping message to the given node.
func (t *UDPv5) Ping(n *znode.Node) error {
	_, err := t.ping(n)
	return err
}

// Resolve searches for a specific node with the given ID and tries to get the most recent
// version of the node record for it. It returns n if the node could not be resolved.
func (t *UDPv5) Resolve(n *znode.Node) *znode.Node {
	if intable := t.tab.getNode(n.ID()); intable != nil && intable.Seq() > n.Seq() {
		n = intable
	}
	// Try asking directly. This works if the node is still responding on the endpoint we have.
	if resp, err := t.RequestZNR(n); err == nil {
		return resp
	}
	// Otherwise do a network lookup.
	result := t.Lookup(n.ID())
	for _, rn := range result {
		if rn.ID() == n.ID() && rn.Seq() > n.Seq() {
			return rn
		}
	}
	return n
}

// AllNodes returns all the nodes stored in the local table.
func (t *UDPv5) AllNodes() []*znode.Node {
	t.tab.mutex.Lock()
	defer t.tab.mutex.Unlock()
	nodes := make([]*znode.Node, 0)

	for _, b := range &t.tab.buckets {
		for _, n := range b.entries {
			nodes = append(nodes, unwrapNode(n))
		}
	}
	return nodes
}

// LocalNode returns the current local node running the
// protocol.
func (t *UDPv5) LocalNode() *znode.LocalNode {
	return t.localNode
}

// RegisterTalkHandler adds a handler for 'talk requests'. The handler function is called
// whenever a request for the given protocol is received and should return the response
// data or nil.
func (t *UDPv5) RegisterTalkHandler(protocol string, handler TalkRequestHandler) {
	t.trlock.Lock()
	defer t.trlock.Unlock()
	t.trhandlers[protocol] = handler
}

// TalkRequest sends a talk request to n and waits for a response.
func (t *UDPv5) TalkRequest(n *znode.Node, protocol string, request []byte) ([]byte, error) {
	req := &v5wire.TalkRequest{Protocol: protocol, Message: request}
	resp := t.call(n, v5wire.TalkResponseMsg, req)
	defer t.callDone(resp)
	select {
	case respMsg := <-resp.ch:
		return respMsg.(*v5wire.TalkResponse).Message, nil
	case err := <-resp.err:
		return nil, err
	}
}

// RandomNodes returns an iterator that finds random nodes in the DHT.
func (t *UDPv5) RandomNodes() znode.Iterator {
	if t.tab.len() == 0 {
		// All nodes were dropped, refresh. The very first query will hit this
		// case and run the bootstrapping logic.
		<-t.tab.refresh()
	}

	return newLookupIterator(t.closeCtx, t.newRandomLookup)
}

// Lookup performs a recursive lookup for the given target.
// It returns the closest nodes to target.
func (t *UDPv5) Lookup(target znode.ID) []*znode.Node {
	return t.newLookup(t.closeCtx, target).run()
}

// lookupRandom looks up a random target.
// This is needed to satisfy the transport interface.
func (t *UDPv5) lookupRandom() []*znode.Node {
	return t.newRandomLookup(t.closeCtx).run()
}

// lookupSelf looks up our own node ID.
// This is needed to satisfy the transport interface.
func (t *UDPv5) lookupSelf() []*znode.Node {
	return t.newLookup(t.closeCtx, t.Self().ID()).run()
}

func (t *UDPv5) newRandomLookup(ctx context.Context) *lookup {
	var target znode.ID
	crand.Read(target[:])
	return t.newLookup(ctx, target)
}

func (t *UDPv5) newLookup(ctx context.Context, target znode.ID) *lookup {
	return newLookup(ctx, t.tab, target, func(n *node) ([]*node, error) {
		return t.lookupWorker(n, target)
	})
}

// lookupWorker performs FINDNODE calls against a single node during lookup.
func (t *UDPv5) lookupWorker(destNode *node, target znode.ID) ([]*node, error) {
	var (
		dists = lookupDistances(target, destNode.ID())
		nodes = nodesByDistance{target: target}
		err   error
	)
	var r []*znode.Node
	r, err = t.findnode(unwrapNode(destNode), dists)
	if errors.Is(err, errClosed) {
		return nil, err
	}
	for _, n := range r {
		if n.ID() != t.Self().ID() {
			nodes.push(wrapNode(n), findnodeResultLimit)
		}
	}
	return nodes.entries, err
}

// lookupDistances computes the distance parameter for FINDNODE calls to dest.
// It chooses distances adjacent to logdist(target, dest), e.g. for a target
// with logdist(target, dest) = 255 the result is [255, 256, 254].
func lookupDistances(target, dest znode.ID) (dists []uint) {
	td := znode.LogDist(target, dest)
	dists = append(dists, uint(td))
	for i := 1; len(dists) < lookupRequestLimit; i++ {
		if td+i < 256 {
			dists = append(dists, uint(td+i))
		}
		if td-i > 0 {
			dists = append(dists, uint(td-i))
		}
	}
	return dists
}

// ping calls PING on a node and waits for a PONG response.
func (t *UDPv5) ping(n *znode.Node) (uint64, error) {
	req := &v5wire.Ping{ZNRSeq: t.localNode.Node().Seq()}
	resp := t.call(n, v5wire.PongMsg, req)
	defer t.callDone(resp)

	select {
	case pong := <-resp.ch:
		return pong.(*v5wire.Pong).ZNRSeq, nil
	case err := <-resp.err:
		return 0, err
	}
}

// RequestZNR requests n's record.
func (t *UDPv5) RequestZNR(n *znode.Node) (*znode.Node, error) {
	nodes, err := t.findnode(n, []uint{0})
	if err != nil {
		return nil, err
	}
	if len(nodes) != 1 {
		return nil, fmt.Errorf("%d nodes in response for distance zero", len(nodes))
	}
	return nodes[0], nil
}

// findnode calls FINDNODE on a node and waits for responses.
func (t *UDPv5) findnode(n *znode.Node, distances []uint) ([]*znode.Node, error) {
	resp := t.call(n, v5wire.NodesMsg, &v5wire.Findnode{Distances: distances})
	return t.waitForNodes(resp, distances)
}

// waitForNodes waits for NODES responses to the given call.
func (t *UDPv5) waitForNodes(c *callV5, distances []uint) ([]*znode.Node, error) {
	defer t.callDone(c)

	var (
		nodes           []*znode.Node
		seen            = make(map[znode.ID]struct{})
		received, total = 0, -1
	)
	for {
		select {
		case responseP := <-c.ch:
			response := responseP.(*v5wire.Nodes)
			for _, record := range response.Nodes {
				node, err := t.verifyResponsznode(c, record, distances, seen)
				if err != nil {
					t.log.Debug("Invalid record in "+response.Name(), "id", c.node.ID(), "err", err)
					continue
				}
				nodes = append(nodes, node)
			}
			if total == -1 {
				total = min(int(response.Total), totalNodesResponseLimit)
			}
			if received++; received == total {
				return nodes, nil
			}
		case err := <-c.err:
			return nodes, err
		}
	}
}

// verifyResponsznode checks validity of a record in a NODES response.
func (t *UDPv5) verifyResponsznode(c *callV5, r *znr.Record, distances []uint, seen map[znode.ID]struct{}) (*znode.Node, error) {
	node, err := znode.New(t.validSchemes, r)
	if err != nil {
		return nil, err
	}
	if err := netutil.CheckRelayIP(c.node.IP(), node.IP()); err != nil {
		return nil, err
	}
	if t.netrestrict != nil && !t.netrestrict.Contains(node.IP()) {
		return nil, errors.New("not contained in netrestrict list")
	}
	if c.node.UDP() <= 1024 {
		return nil, errLowPort
	}
	if distances != nil {
		nd := znode.LogDist(c.node.ID(), node.ID())
		if !containsUint(uint(nd), distances) {
			return nil, errors.New("does not match any requested distance")
		}
	}
	if _, ok := seen[node.ID()]; ok {
		return nil, fmt.Errorf("duplicate record")
	}
	seen[node.ID()] = struct{}{}
	return node, nil
}

func containsUint(x uint, xs []uint) bool {
	for _, v := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// call sends the given call and sets up a handler for response packets (of message type
// responseType). Responses are dispatched to the call's response channel.
func (t *UDPv5) call(node *znode.Node, responseType byte, packet v5wire.Packet) *callV5 {
	c := &callV5{
		node:         node,
		packet:       packet,
		responseType: responseType,
		reqid:        make([]byte, 8),
		ch:           make(chan v5wire.Packet, 1),
		err:          make(chan error, 1),
	}
	// Assign request ID.
	crand.Read(c.reqid)
	packet.SetRequestID(c.reqid)
	// Send call to dispatch.
	select {
	case t.callCh <- c:
	case <-t.closeCtx.Done():
		c.err <- errClosed
	}
	return c
}

// callDone tells dispatch that the active call is done.
func (t *UDPv5) callDone(c *callV5) {
	// This needs a loop because further responses may be incoming until the
	// send to callDoneCh has completed. Such responses need to be discarded
	// in order to avoid blocking the dispatch loop.
	for {
		select {
		case <-c.ch:
			// late response, discard.
		case <-c.err:
			// late error, discard.
		case t.callDoneCh <- c:
			return
		case <-t.closeCtx.Done():
			return
		}
	}
}

// dispatch runs in its own goroutine, handles incoming packets and deals with calls.
//
// For any destination node there is at most one 'active call', stored in the t.activeCall*
// maps. A call is made active when it is sent. The active call can be answered by a
// matching response, in which case c.ch receives the response; or by timing out, in which case
// c.err receives the error. When the function that created the call signals the active
// call is done through callDone, the next call from the call queue is started.
//
// Calls may also be answered by a WHOAREYOU packet referencing the call packet's authTag.
// When that happens the call is simply re-sent to complete the handshake. We allow one
// handshake attempt per call.
func (t *UDPv5) dispatch() {
	defer t.wg.Done()

	// Arm first read.
	t.readNextCh <- struct{}{}

	for {
		select {
		case c := <-t.callCh:
			id := c.node.ID()
			t.callQueue[id] = append(t.callQueue[id], c)
			t.sendNextCall(id)

		case ct := <-t.respTimeoutCh:
			active := t.activeCallByNode[ct.c.node.ID()]
			if ct.c == active && ct.timer == active.timeout {
				ct.c.err <- errTimeout
			}

		case c := <-t.callDoneCh:
			id := c.node.ID()
			active := t.activeCallByNode[id]
			if active != c {
				panic("BUG: callDone for inactive call")
			}
			c.timeout.Stop()
			delete(t.activeCallByAuth, c.nonce)
			delete(t.activeCallByNode, id)
			t.sendNextCall(id)

		case p := <-t.packetInCh:
			t.handlePacket(p.Data, p.Addr)
			// Arm next read.
			t.readNextCh <- struct{}{}

		case <-t.closeCtx.Done():
			close(t.readNextCh)
			for id, queue := range t.callQueue {
				for _, c := range queue {
					c.err <- errClosed
				}
				delete(t.callQueue, id)
			}
			for id, c := range t.activeCallByNode {
				c.err <- errClosed
				delete(t.activeCallByNode, id)
				delete(t.activeCallByAuth, c.nonce)
			}
			return
		}
	}
}

// startResponseTimeout sets the response timer for a call.
func (t *UDPv5) startResponseTimeout(c *callV5) {
	if c.timeout != nil {
		c.timeout.Stop()
	}
	var (
		timer mclock.Timer
		done  = make(chan struct{})
	)
	timer = t.clock.AfterFunc(respTimeoutV5, func() {
		<-done
		select {
		case t.respTimeoutCh <- &callTimeout{c, timer}:
		case <-t.closeCtx.Done():
		}
	})
	c.timeout = timer
	close(done)
}

// sendNextCall sends the next call in the call queue if there is no active call.
func (t *UDPv5) sendNextCall(id znode.ID) {
	queue := t.callQueue[id]
	if len(queue) == 0 || t.activeCallByNode[id] != nil {
		return
	}
	t.activeCallByNode[id] = queue[0]
	t.sendCall(t.activeCallByNode[id])
	if len(queue) == 1 {
		delete(t.callQueue, id)
	} else {
		copy(queue, queue[1:])
		t.callQueue[id] = queue[:len(queue)-1]
	}
}

// sendCall encodes and sends a request packet to the call's recipient node.
// This performs a handshake if needed.
func (t *UDPv5) sendCall(c *callV5) {
	// The call might have a nonce from a previous handshake attempt. Remove the entry for
	// the old nonce because we're about to generate a new nonce for this call.
	if c.nonce != (v5wire.Nonce{}) {
		delete(t.activeCallByAuth, c.nonce)
	}

	addr := &net.UDPAddr{IP: c.node.IP(), Port: c.node.UDP()}
	newNonce, _ := t.send(c.node.ID(), addr, c.packet, c.challenge)
	c.nonce = newNonce
	t.activeCallByAuth[newNonce] = c
	t.startResponseTimeout(c)
}

// sendResponse sends a response packet to the given node.
// This doesn't trigger a handshake even if no keys are available.
func (t *UDPv5) sendResponse(toID znode.ID, toAddr *net.UDPAddr, packet v5wire.Packet) error {
	_, err := t.send(toID, toAddr, packet, nil)
	return err
}

// send sends a packet to the given node.
func (t *UDPv5) send(toID znode.ID, toAddr *net.UDPAddr, packet v5wire.Packet, c *v5wire.Whoareyou) (v5wire.Nonce, error) {
	addr := toAddr.String()
	enc, nonce, err := t.codec.Encode(toID, addr, packet, c)
	if err != nil {
		t.log.Warn(">> "+packet.Name(), "id", toID, "addr", addr, "err", err)
		return nonce, err
	}
	_, err = t.conn.WriteToUDP(enc, toAddr)
	t.log.Trace(">> "+packet.Name(), "id", toID, "addr", addr)
	return nonce, err
}

// readLoop runs in its own goroutine and reads packets from the network.
func (t *UDPv5) readLoop() {
	defer t.wg.Done()

	buf := make([]byte, maxPacketSize)
	for range t.readNextCh {
		nbytes, from, err := t.conn.ReadFromUDP(buf)
		if netutil.IsTemporaryError(err) {
			// Ignore temporary read errors.
			t.log.Debug("Temporary UDP read error", "err", err)
			continue
		} else if err != nil {
			// Shut down the loop for permanent errors.
			if !errors.Is(err, io.EOF) {
				t.log.Debug("UDP read error", "err", err)
			}
			return
		}
		t.dispatchReadPacket(from, buf[:nbytes])
	}
}

// dispatchReadPacket sends a packet into the dispatch loop.
func (t *UDPv5) dispatchReadPacket(from *net.UDPAddr, content []byte) bool {
	select {
	case t.packetInCh <- ReadPacket{content, from}:
		return true
	case <-t.closeCtx.Done():
		return false
	}
}

// handlePacket decodes and processes an incoming packet from the network.
func (t *UDPv5) handlePacket(rawpacket []byte, fromAddr *net.UDPAddr) error {
	addr := fromAddr.String()
	fromID, fromNode, packet, err := t.codec.Decode(rawpacket, addr)
	if err != nil {
		t.log.Debug("Bad discv5 packet", "id", fromID, "addr", addr, "err", err)
		return err
	}
	if fromNode != nil {
		// Handshake succeeded, add to table.
		t.tab.addSeenNode(wrapNode(fromNode))
	}
	if packet.Kind() != v5wire.WhoareyouPacket {
		// WHOAREYOU logged separately to report errors.
		t.log.Trace("<< "+packet.Name(), "id", fromID, "addr", addr)
	}
	t.handle(packet, fromID, fromAddr)
	return nil
}

// handleCallResponse dispatches a response packet to the call waiting for it.
func (t *UDPv5) handleCallResponse(fromID znode.ID, fromAddr *net.UDPAddr, p v5wire.Packet) bool {
	ac := t.activeCallByNode[fromID]
	if ac == nil || !bytes.Equal(p.RequestID(), ac.reqid) {
		t.log.Debug(fmt.Sprintf("Unsolicited/late %s response", p.Name()), "id", fromID, "addr", fromAddr)
		return false
	}
	if !fromAddr.IP.Equal(ac.node.IP()) || fromAddr.Port != ac.node.UDP() {
		t.log.Debug(fmt.Sprintf("%s from wrong endpoint", p.Name()), "id", fromID, "addr", fromAddr)
		return false
	}
	if p.Kind() != ac.responseType {
		t.log.Debug(fmt.Sprintf("Wrong discv5 response type %s", p.Name()), "id", fromID, "addr", fromAddr)
		return false
	}
	t.startResponseTimeout(ac)
	ac.ch <- p
	return true
}

// getNode looks for a node record in table and database.
func (t *UDPv5) getNode(id znode.ID) *znode.Node {
	if n := t.tab.getNode(id); n != nil {
		return n
	}
	if n := t.localNode.Database().Node(id); n != nil {
		return n
	}
	return nil
}

// handle processes incoming packets according to their message type.
func (t *UDPv5) handle(p v5wire.Packet, fromID znode.ID, fromAddr *net.UDPAddr) {
	switch p := p.(type) {
	case *v5wire.Unknown:
		t.handleUnknown(p, fromID, fromAddr)
	case *v5wire.Whoareyou:
		t.handleWhoareyou(p, fromID, fromAddr)
	case *v5wire.Ping:
		t.handlePing(p, fromID, fromAddr)
	case *v5wire.Pong:
		if t.handleCallResponse(fromID, fromAddr, p) {
			t.localNode.UDPEndpointStatement(fromAddr, &net.UDPAddr{IP: p.ToIP, Port: int(p.ToPort)})
		}
	case *v5wire.Findnode:
		t.handleFindnode(p, fromID, fromAddr)
	case *v5wire.Nodes:
		t.handleCallResponse(fromID, fromAddr, p)
	case *v5wire.TalkRequest:
		t.handleTalkRequest(p, fromID, fromAddr)
	case *v5wire.TalkResponse:
		t.handleCallResponse(fromID, fromAddr, p)
	}
}

// handleUnknown initiates a handshake by responding with WHOAREYOU.
func (t *UDPv5) handleUnknown(p *v5wire.Unknown, fromID znode.ID, fromAddr *net.UDPAddr) {
	challenge := &v5wire.Whoareyou{Nonce: p.Nonce}
	crand.Read(challenge.IDNonce[:])
	if n := t.getNode(fromID); n != nil {
		challenge.Node = n
		challenge.RecordSeq = n.Seq()
	}
	t.sendResponse(fromID, fromAddr, challenge)
}

var (
	errChallengeNoCall = errors.New("no matching call")
	errChallengeTwice  = errors.New("second handshake")
)

// handleWhoareyou resends the active call as a handshake packet.
func (t *UDPv5) handleWhoareyou(p *v5wire.Whoareyou, fromID znode.ID, fromAddr *net.UDPAddr) {
	c, err := t.matchWithCall(fromID, p.Nonce)
	if err != nil {
		t.log.Debug("Invalid "+p.Name(), "addr", fromAddr, "err", err)
		return
	}

	// Resend the call that was answered by WHOAREYOU.
	t.log.Trace("<< "+p.Name(), "id", c.node.ID(), "addr", fromAddr)
	c.handshakeCount++
	c.challenge = p
	p.Node = c.node
	t.sendCall(c)
}

// matchWithCall checks whether a handshake attempt matches the active call.
func (t *UDPv5) matchWithCall(fromID znode.ID, nonce v5wire.Nonce) (*callV5, error) {
	c := t.activeCallByAuth[nonce]
	if c == nil {
		return nil, errChallengeNoCall
	}
	if c.handshakeCount > 0 {
		return nil, errChallengeTwice
	}
	return c, nil
}

// handlePing sends a PONG response.
func (t *UDPv5) handlePing(p *v5wire.Ping, fromID znode.ID, fromAddr *net.UDPAddr) {
	remoteIP := fromAddr.IP
	// Handle IPv4 mapped IPv6 addresses in the
	// event the local node is binded to an
	// ipv6 interface.
	if remoteIP.To4() != nil {
		remoteIP = remoteIP.To4()
	}
	t.sendResponse(fromID, fromAddr, &v5wire.Pong{
		ReqID:  p.ReqID,
		ToIP:   remoteIP,
		ToPort: uint16(fromAddr.Port),
		ZNRSeq: t.localNode.Node().Seq(),
	})
}

// handleFindnode returns nodes to the requester.
func (t *UDPv5) handleFindnode(p *v5wire.Findnode, fromID znode.ID, fromAddr *net.UDPAddr) {
	nodes := t.collectTablznodes(fromAddr.IP, p.Distances, findnodeResultLimit)
	for _, resp := range packNodes(p.ReqID, nodes) {
		t.sendResponse(fromID, fromAddr, resp)
	}
}

// collectTablznodes creates a FINDNODE result set for the given distances.
func (t *UDPv5) collectTablznodes(rip net.IP, distances []uint, limit int) []*znode.Node {
	var nodes []*znode.Node
	var processed = make(map[uint]struct{})
	for _, dist := range distances {
		// Reject duplicate / invalid distances.
		_, seen := processed[dist]
		if seen || dist > 256 {
			continue
		}

		// Get the nodes.
		var bn []*znode.Node
		if dist == 0 {
			bn = []*znode.Node{t.Self()}
		} else if dist <= 256 {
			t.tab.mutex.Lock()
			bn = unwrapNodes(t.tab.bucketAtDistance(int(dist)).entries)
			t.tab.mutex.Unlock()
		}
		processed[dist] = struct{}{}

		// Apply some pre-checks to avoid sending invalid nodes.
		for _, n := range bn {
			// TODO livenessChecks > 1
			if netutil.CheckRelayIP(rip, n.IP()) != nil {
				continue
			}
			nodes = append(nodes, n)
			if len(nodes) >= limit {
				return nodes
			}
		}
	}
	return nodes
}

// packNodes creates NODES response packets for the given node list.
func packNodes(reqid []byte, nodes []*znode.Node) []*v5wire.Nodes {
	if len(nodes) == 0 {
		return []*v5wire.Nodes{{ReqID: reqid, Total: 1}}
	}

	total := uint8(math.Ceil(float64(len(nodes)) / 3))
	var resp []*v5wire.Nodes
	for len(nodes) > 0 {
		p := &v5wire.Nodes{ReqID: reqid, Total: total}
		items := min(nodesResponseItemLimit, len(nodes))
		for i := 0; i < items; i++ {
			p.Nodes = append(p.Nodes, nodes[i].Record())
		}
		nodes = nodes[items:]
		resp = append(resp, p)
	}
	return resp
}

// handleTalkRequest runs the talk request handler of the requested protocol.
func (t *UDPv5) handleTalkRequest(p *v5wire.TalkRequest, fromID znode.ID, fromAddr *net.UDPAddr) {
	t.trlock.Lock()
	handler := t.trhandlers[p.Protocol]
	t.trlock.Unlock()

	var response []byte
	if handler != nil {
		response = handler(fromID, fromAddr, p.Message)
	}
	resp := &v5wire.TalkResponse{ReqID: p.ReqID, Message: response}
	t.sendResponse(fromID, fromAddr, resp)
}
