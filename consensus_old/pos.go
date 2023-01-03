package consensus_old

import (
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	common2 "github.com/theQRL/go-qrllib/common"
	"github.com/theQRL/go-qrllib/dilithium"
	"github.com/theQRL/zond/block"
	"github.com/theQRL/zond/chain"
	"github.com/theQRL/zond/config"
	"github.com/theQRL/zond/db"
	"github.com/theQRL/zond/keys"
	"github.com/theQRL/zond/metadata"
	"github.com/theQRL/zond/misc"
	"github.com/theQRL/zond/ntp"
	"github.com/theQRL/zond/p2p"
	"github.com/theQRL/zond/protos"
	"github.com/theQRL/zond/transactions"
)

type POS struct {
	config *config.Config
	srv    *p2p.ServerV1
	chain  *chain.Chain
	db     *db.DB

	/*
		validators stores the dilithium based on seed available
		in the local storage for staking.Dilithium PK is the key
		of this map
	*/
	validators map[string]*dilithium.Dilithium

	exit                        chan struct{}
	loopWG                      sync.WaitGroup
	blockReceivedForAttestation chan *block.Block
	attestationReceivedForBlock chan *transactions.Attest

	blockBeingAttested     *block.Block // Block being proposed by this node and
	slotValidatorsMetaData *metadata.SlotValidatorsMetaData
	// awaiting for the attestations
	attestors    [][]byte
	attestations []*transactions.Attest
}

func (p *POS) Start() {
	/* TODO
	1. Load Dilithium Keys from file based in config
	2. Check if Stake Enabled
	3.
	*/

	/* Scenarios
	1.
	Block coming to Chain. After adding to block, Chain calls POS,
	with next slotleader dilithium address
	POS checks if the slotleader private key is present. If present
	then load the private key, make the blog, broadcast the unsigned,
	block for attestation

	2.
	Block was not received within a specific block timing.
	POS is called with next slot leader due to timeout,
	then check if next slotleader key is present

	*/

	/*
		POS will call itself after every

		1. sleep for next slot time - current time
		2. On Timer, check if slot leader is one of the address from wallet
		3. If yes, then fetch last block from Chain, create a new block,
		   broadcast it to server for attestation
		4. Keep adding attestation to the block, as soon as a threshold,
		   sign the block and broadcast it.
		5.

	*/
}

func (p *POS) PendingBlock() *block.Block {
	return p.blockBeingAttested
}

func (p *POS) TimeRemainingForNextAction() time.Duration {
	isThisNodeProposer := false
	if p.blockBeingAttested != nil {
		proposerDilithiumPK := misc.BytesToHexStr(p.blockBeingAttested.ProtocolTransactions()[0].Pk)
		_, isThisNodeProposer = p.validators[proposerDilithiumPK]
	}
	if p.blockBeingAttested == nil || !isThisNodeProposer {
		// Wait time to propose the block
		currentTime := uint64(time.Now().Unix())
		genesisTimestamp := p.config.Dev.Genesis.GenesisTimestamp
		blockTiming := p.config.Dev.BlockTime

		currentSlot := (currentTime - genesisTimestamp) / blockTiming
		nextSlotTime := genesisTimestamp + (currentSlot+1)*blockTiming

		timeRemainingForNextSlot := nextSlotTime - currentTime
		return time.Duration(timeRemainingForNextSlot) * time.Second
	} else {
		// If block has been proposed by this node,
		// then max wait time to collect attestor txn
		// before broadcasting the block
		currentTime := uint64(time.Now().Unix())
		slotNumber := p.blockBeingAttested.SlotNumber()
		genesisTimestamp := p.config.Dev.Genesis.GenesisTimestamp
		blockTiming := p.config.Dev.BlockTime
		// TODO: move this 45 seconds into config
		return time.Duration(
			(genesisTimestamp+slotNumber*blockTiming+45)-currentTime) * time.Second
	}
}

func (p *POS) GetCurrentSlot() uint64 {
	currentTime := uint64(time.Now().Unix())
	genesisTimestamp := p.config.Dev.Genesis.GenesisTimestamp
	blockTiming := p.config.Dev.BlockTime

	return (currentTime - genesisTimestamp) / blockTiming
}

func (p *POS) Run() {
	p.loopWG.Add(1)
	defer p.loopWG.Done()

running:
	for {
		select {
		case <-p.exit:
			log.Info("Shutting Down POS")
			break running
		case <-time.After(p.TimeRemainingForNextAction()):
			if !p.config.User.Stake.EnableStaking {
				continue
			}
			isThisNodeProposer := false
			if p.blockBeingAttested != nil {
				proposerDilithiumPK := misc.BytesToHexStr(p.blockBeingAttested.ProtocolTransactions()[0].Pk)
				_, isThisNodeProposer = p.validators[proposerDilithiumPK]
				if !isThisNodeProposer {
					p.blockBeingAttested = nil
				}
			}
			if p.blockBeingAttested == nil {
				lastBlock := p.chain.GetLastBlock()
				lastBlockMetaData, err := p.chain.GetBlockMetaData(lastBlock.Hash())
				if err != nil {
					log.Error("Failed to get last block metadata")
					continue
				}

				slotNumber := p.GetCurrentSlot()
				slotLeaderPK, err := p.chain.GetSlotLeaderDilithiumPKBySlotNumber(lastBlockMetaData.TrieRoot(),
					slotNumber, lastBlock.Hash())

				slotValidatorsMetaData, err := p.chain.GetSlotValidatorsMetaDataBySlotNumber(lastBlockMetaData.TrieRoot(), slotNumber, lastBlock.Hash())
				if err != nil {
					log.Error("Failed to Get Parent Block ", err.Error())
					continue
				}
				// This is required in case the node receives attestation for the block from other nodes
				p.slotValidatorsMetaData = slotValidatorsMetaData

				if err != nil {
					log.Error("Error getting SlotLeader Dilithium PK By Slot Number ", err.Error())
					continue
				}
				proposerD, ok := p.validators[misc.BytesToHexStr(slotLeaderPK)]
				if !ok {
					continue
				}

				log.Info("Minting Block #", slotNumber)
				txPool := p.chain.GetTransactionPool()
				txs := make([]*protos.Transaction, 0)
				// TODO: Replace hardcoded 100 with some max block size
				for i := 0; i < 100; {
					txInfo := txPool.Pop()
					if txInfo == nil {
						break
					}
					txInterface := txInfo.Transaction()
					txPBData := txInterface.PBData()
					txHash := txInterface.Hash()
					strTxHash := misc.BytesToHexStr(txHash[:])
					if err := p.chain.ValidateTransaction(txPBData); err != nil {
						log.Error(err.Error())
						continue
					}
					txs = append(txs, txPBData)
					log.Info("Added transaction ", strTxHash, " into block #", slotNumber)
					i++
				}

				statedb, err := p.chain.AccountDBForTrie(lastBlockMetaData.TrieRoot())
				if err != nil {
					log.Error("failed to get statedb")
					continue
				}
				pk := proposerD.GetPK()
				signerNonce := statedb.GetNonce(dilithium.GetDilithiumAddressFromPK(pk))
				b := block.NewBlock(config.GetDevConfig().ChainID.Uint64(), ntp.GetNTP().Time(), pk[:], slotNumber,
					lastBlock.Hash(), txs, nil, signerNonce)

				attestors, err := p.chain.GetAttestorsBySlotNumber(lastBlockMetaData.TrieRoot(), b.SlotNumber(), b.ParentHash())
				if err != nil {
					log.Error("Error while getting Attestors by Slot Number ", err.Error())
					continue
				}
				p.blockBeingAttested = b
				p.attestors = attestors
				p.attestations = make([]*transactions.Attest, 0)
				for _, dilithiumPK := range attestors {
					strDilithiumPK := misc.BytesToHexStr(dilithiumPK)
					d, ok := p.validators[strDilithiumPK]
					if !ok {
						continue
					}
					attestorNonce := statedb.GetNonce(dilithium.GetDilithiumAddressFromPK(d.GetPK()))
					attestTx, err := b.Attest(config.GetDevConfig().ChainID.Uint64(), d, attestorNonce)
					if err != nil {
						log.Error("Error while Attesting ", err.Error())
					}
					p.attestations = append(p.attestations, attestTx)
					p.blockBeingAttested.AddAttestTx(attestTx)
				}

				// In case of all attestors for this slot belongs to same node
				// then we already have all attestors, and we should broadcast
				// the block
				if len(p.attestations) == len(attestors) {
					p.blockBeingAttested.SignByProposer(proposerD)
					b = p.blockBeingAttested
					p.blockBeingAttested = nil
					p.attestations = make([]*transactions.Attest, 0)

					if !p.chain.AddBlock(b) {
						log.Error("Error adding block proposed by this Node")
						continue
					}
					p.srv.BroadcastBlock(b)
					continue
				}

				/*
					1. If any attestation remaining,
					then Broadcast Unsigned block via server for attestation
					2. Optimization needed PartialBlockSigningHash is called two times
				*/
				partialBlockSigningHash := b.PartialBlockSigningHash()
				log.Info("Broadcasting Block #", slotNumber, " for attestation")
				p.srv.BroadcastBlockForAttestation(b, proposerD.Sign(partialBlockSigningHash[:]))

			} else {
				// TODO:
				// Check if block has sufficient attestation
				// If yes then add block to the chain and
				// broadcast the block
				if len(p.blockBeingAttested.ProtocolTransactions()) > 1 {
					log.Info("Number of Attestations Received ",
						len(p.blockBeingAttested.ProtocolTransactions())-1,
						" for Block #", p.blockBeingAttested.SlotNumber())
					dilithiumPK := misc.BytesToHexStr(p.blockBeingAttested.ProtocolTransactions()[0].Pk)
					proposerD, ok := p.validators[dilithiumPK]
					if !ok {
						log.Error("Failed to load dilithium wallet for ", dilithiumPK)
						continue
					}
					p.blockBeingAttested.SignByProposer(proposerD)
					p.chain.AddBlock(p.blockBeingAttested)
					p.srv.BroadcastBlock(p.blockBeingAttested)
				} else {
					log.Info("Insufficient attestation for Block #",
						p.blockBeingAttested.SlotNumber())
					txPool := p.chain.GetTransactionPool()
					err := txPool.AddTxFromBlock(p.blockBeingAttested, p.chain.Height())
					if err != nil {
						log.Error("Failed to add transaction from block to pool ",
							err.Error())
					}
				}

				p.blockBeingAttested = nil
				p.attestations = make([]*transactions.Attest, 0)
			}
		case b := <-p.blockReceivedForAttestation:
			if !p.config.User.Stake.EnableStaking {
				continue
			}
			/*
				This case happens, when the block is proposed by some outside node.
			*/
			/*
				TODO:
				Check if block slot number must be equal to the current expected slot number
				check if the block slot leader is correct
				Don't accept Block for attestation after certain threshold
			*/

			lastBlock := p.chain.GetLastBlock()
			if !reflect.DeepEqual(b.ParentHash(), lastBlock.Hash()) {
				continue
			}

			if p.blockBeingAttested != nil && p.blockBeingAttested.SlotNumber() == b.SlotNumber() {
				continue
			}

			parentBlockMetaData, err := p.chain.GetBlockMetaData(b.ParentHash())
			if err != nil {
				log.Error("Failed to Get Parent Block Metadata ", err.Error())
				continue
			}

			//parentBlock, err := p.chain.GetBlock(b.ParentHash())
			//if err != nil {
			//	log.Error("Failed to Get Parent Block ", err.Error())
			//	continue
			//}
			//attestors, err := p.chain.GetAttestorsBySlotNumber(b.SlotNumber(), b.ParentHash())
			//if err != nil {
			//	log.Error("Error while getting Attestors by Slot Number ", err.Error())
			//	continue
			//}
			blockProposerPK := b.ProtocolTransactions()[0].GetPk()
			//slotLeader, err := p.chain.GetSlotLeaderDilithiumPKBySlotNumber(b.SlotNumber(), lastBlock.Hash())

			slotValidatorsMetaData, err := p.chain.GetSlotValidatorsMetaDataBySlotNumber(parentBlockMetaData.TrieRoot(), b.SlotNumber(), b.ParentHash())
			if err != nil {
				log.Error("Failed to Get Parent Block ", err.Error())
				continue
			}

			if !slotValidatorsMetaData.IsSlotLeader(misc.BytesToHexStr(blockProposerPK)) {
				expectedDilithiumAddress := misc.GetDilithiumAddressFromUnSizedPK(slotValidatorsMetaData.GetSlotLeaderPK())
				foundDilithiumAddress := misc.GetDilithiumAddressFromUnSizedPK(blockProposerPK)

				log.Error("Block received for attestation by unexpected slotLeader/blockProposer ")
				log.Error("Expected Slot Leader ", expectedDilithiumAddress)
				log.Error("Found Slot Leader ", foundDilithiumAddress)
				continue
			}

			p.blockBeingAttested = b
			p.slotValidatorsMetaData = slotValidatorsMetaData
			log.Info("Block #", b.SlotNumber(), " received for attestation")
			partialBlockSigningHash := b.PartialBlockSigningHash()
			statedb, err := p.chain.AccountDBForTrie(parentBlockMetaData.TrieRoot())
			for strDilithiumPK, d := range p.validators {
				if !slotValidatorsMetaData.IsAttestor(strDilithiumPK) {
					continue
				}
				attestorNonce := statedb.GetNonce(dilithium.GetDilithiumAddressFromPK(d.GetPK()))
				attestTx, err := b.Attest(config.GetDevConfig().ChainID.Uint64(), d, attestorNonce)
				if err != nil {
					log.Error("Error while Attesting ", err.Error())
					continue
				}
				p.srv.BroadcastAttestationTransaction(attestTx,
					b.SlotNumber(),
					blockProposerPK,
					b.ParentHash(),
					partialBlockSigningHash)
			}
		case tx := <-p.attestationReceivedForBlock:
			if !p.config.User.Stake.EnableStaking {
				continue
			}
			if p.blockBeingAttested == nil {
				continue
			}
			/*
				When the attestation is received, check if the attest transaction is for the block
				proposed by this node.
			*/

			// Validate Txn
			//epochMetaData, err := metadata.GetEpochMetaData(p.db, p.blockBeingAttested.SlotNumber(),
			//	p.blockBeingAttested.ParentHash())
			//if err != nil {
			//	log.Error("Error getting epochMetaData")
			//	continue
			//}
			//finalizedHeaderHash, err := p.chain.GetFinalizedHeaderHash()
			//if err != nil {
			//	log.Error("[POS] Failed to GetFinalizedHeaderHash ", err.Error())
			//	continue
			//}
			partialBlockSigningHash := p.blockBeingAttested.PartialBlockSigningHash()
			//sc, err := state.NewStateContext(p.db, p.blockBeingAttested.SlotNumber(),
			//	p.blockBeingAttested.ProtocolTransactions()[0].Pk,
			//	finalizedHeaderHash,
			//	p.blockBeingAttested.ParentHash(),
			//	p.blockBeingAttested.Hash(),
			//	partialBlockSigningHash,
			//	common.Hash{},
			//	epochMetaData)
			//if err != nil {
			//	log.Error("Error creating NewStateContext")
			//	continue
			//}
			parentBlock, err := p.chain.GetBlock(p.blockBeingAttested.ParentHash())
			if err != nil {
				log.Warn("failed to load parent block ", err)
				continue
			}
			if err := p.chain.ValidateAttestTransaction(tx.PBData(), p.slotValidatorsMetaData, p.blockBeingAttested.PartialBlockSigningHash(), p.blockBeingAttested.SlotNumber(), parentBlock.SlotNumber()); err != nil {
				log.Warn("Attestor transaction validation failed: ", err)
				continue
			}

			// Ignore duplicate Attest Transaction
			isDuplicate := false
			for _, oldTx := range p.attestations {
				if reflect.DeepEqual(oldTx.PK(), tx.PK()) {
					isDuplicate = true
					break
				}
			}
			if isDuplicate {
				continue
			}

			p.attestations = append(p.attestations, tx)
			txHash := tx.TxHash(tx.GetSigningHash(partialBlockSigningHash))
			log.Info("Received Attest Transaction ",
				misc.BytesToHexStr(txHash[:]),
				" for block #", p.blockBeingAttested.SlotNumber())

			// Add received attestation into block
			p.blockBeingAttested.AddAttestTx(tx)

			// Check if all attestations has been received, if yes, then broadcast block
			//if len(p.attestations) == len(p.attestors) {
			//	slotLeader := p.blockBeingAttested.ProtocolTransactions()[0].Pk
			//	proposerD, ok := p.validators[misc.BytesToHexStr(slotLeader)]
			//	if !ok {
			//		continue
			//	}
			//	p.blockBeingAttested.SignByProposer(proposerD)
			//	p.srv.BroadcastBlock(p.blockBeingAttested)
			//	p.blockBeingAttested = nil
			//	p.attestations = make([]*transactions.Attest, 0)
			//}
		}
	}
}

func (p *POS) Stop() {
	close(p.exit)
	p.loopWG.Wait()

	return
}

func NewPOS(srv *p2p.ServerV1, chain *chain.Chain, db *db.DB) *POS {
	pos := &POS{
		config:     config.GetConfig(),
		srv:        srv,
		chain:      chain,
		db:         db,
		validators: make(map[string]*dilithium.Dilithium),
		exit:       make(chan struct{}),

		blockReceivedForAttestation: srv.GetBlockReceivedForAttestation(),
		attestationReceivedForBlock: srv.GetAttestationReceivedForBlock(),
	}

	dk := keys.NewDilithiumKeys(pos.config.User.Stake.DilithiumKeysFileName)
	for i, dilithiumInfo := range dk.GetDilithiumInfo() {
		strPK := dilithiumInfo.PK
		pk, err := misc.HexStrToBytes(strPK)
		if err != nil {
			log.Error("Error decoding Dilithium PK ", err.Error())
			return nil
		}
		sk, err := misc.HexStrToBytes(dilithiumInfo.SK)
		if err != nil {
			log.Error("Error decoding Dilithium SK ", err.Error())
			return nil
		}

		var pkSized [dilithium.PKSizePacked]uint8
		var skSized [dilithium.SKSizePacked]uint8
		copy(pkSized[:], pk)
		copy(skSized[:], sk)

		binData, err := misc.HexStrToBytes(dilithiumInfo.HexSeed)
		var binSeed [common2.SeedSize]uint8
		copy(binSeed[:], binData)

		if err != nil {
			log.Errorf("failed to decode hex seed for dilithium at index %d", i)
			return nil
		}
		pos.validators[strPK] = dilithium.NewDilithiumFromSeed(binSeed)
		if !reflect.DeepEqual(pos.validators[strPK].GetPK(), pkSized) {
			log.Error("dilithium pk mismatch")
			return nil
		}
		if !reflect.DeepEqual(pos.validators[strPK].GetSK(), skSized) {
			log.Error("dilithium sk mismatch")
			return nil
		}
	}

	return pos
}
