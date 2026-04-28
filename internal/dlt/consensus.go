package dlt

import (
	"fmt"
	"log/slog"
	"sync"
)

// ConsensusEngine orchestrates a simple 2-phase consensus protocol
// (propose -> vote -> commit) across a set of validators. It uses a
// ValidatorTransport to deliver messages; in single-process mode this
// is a LocalTransport (in-process channels), and in multi-node mode
// a SCIONTransport over real SCION/UDP connections.
type ConsensusEngine struct {
	mu         sync.Mutex
	ledger     *Ledger
	validators []ValidatorState
	transport  ValidatorTransport
}

// NewConsensusEngine creates a consensus engine backed by the given ledger.
// It uses an internal LocalTransport so all existing call sites work unchanged.
func NewConsensusEngine(ledger *Ledger, validators []ValidatorState) *ConsensusEngine {
	// Build a local transport set; the engine uses the first validator's inbox
	// but in single-process mode the transport is only used for the propose→vote→commit
	// loop which runs synchronously in proposeVoteCommitLocked.
	ids := make([]string, len(validators))
	for i, v := range validators {
		ids[i] = v.ID
	}
	var transport ValidatorTransport
	if len(ids) > 0 {
		transports := NewLocalTransportSet(ids)
		transport = transports[ids[0]]
	}
	return &ConsensusEngine{
		ledger:     ledger,
		validators: validators,
		transport:  transport,
	}
}

// NewConsensusEngineWithTransport creates a consensus engine with an explicit
// transport, used when validators communicate over real SCION networking.
func NewConsensusEngineWithTransport(ledger *Ledger, validators []ValidatorState, transport ValidatorTransport) *ConsensusEngine {
	return &ConsensusEngine{
		ledger:     ledger,
		validators: validators,
		transport:  transport,
	}
}

// RunRound orchestrates a full consensus round for a single transaction:
//  1. Submit the transaction to the ledger's pending pool.
//  2. The first validator proposes a block.
//  3. All validators vote on the proposal.
//  4. If a majority votes yes, the transaction is committed.
func (ce *ConsensusEngine) RunRound(tx *Transaction) (*ConsensusResult, error) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	slog.Debug("starting consensus round", "tx_id", tx.ID, "from", tx.From, "to", tx.To, "amount", tx.Amount, "currency", tx.Currency)

	if err := ce.ledger.SubmitTransaction(tx); err != nil {
		return &ConsensusResult{
			Confirmed: false,
			TxID:      tx.ID,
		}, err
	}

	return ce.proposeVoteCommitLocked(tx)
}

// SubmitAndRunRound atomically submits a transaction (if absent) and runs
// consensus under a single lock, closing the gap between submit and round.
// Returns (existing *Transaction, result, error). If existing is non-nil,
// the transaction was already seen and no round was run.
func (ce *ConsensusEngine) SubmitAndRunRound(tx *Transaction) (*Transaction, *ConsensusResult, error) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	existing, err := ce.ledger.SubmitTransactionIfAbsent(tx)
	if existing != nil || err != nil {
		return existing, nil, err
	}

	result, err := ce.proposeVoteCommitLocked(tx)
	return nil, result, err
}

// RunRoundFromPending runs consensus for a transaction that's already in the
// pending pool (submitted via SubmitTransactionIfAbsent). Skips the submit step.
func (ce *ConsensusEngine) RunRoundFromPending(tx *Transaction) (*ConsensusResult, error) {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	return ce.proposeVoteCommitLocked(tx)
}

// proposeVoteCommitLocked runs the propose→vote→commit consensus phases.
// Caller must hold ce.mu. The transaction must already be in the pending pool.
//
// This method runs all validators synchronously via direct ledger calls,
// keeping the local-transport path identical to the original behavior.
// The transport is used by ValidatorNode for multi-node consensus.
func (ce *ConsensusEngine) proposeVoteCommitLocked(tx *Transaction) (*ConsensusResult, error) {
	if len(ce.validators) == 0 {
		ce.ledger.CleanupPending(tx.ID)
		return &ConsensusResult{Confirmed: false, TxID: tx.ID},
			fmt.Errorf("no validators configured")
	}
	proposer := ce.validators[0].ID
	proposal, err := ce.ledger.ProposeBlock(proposer)
	if err != nil {
		ce.ledger.CleanupPending(tx.ID)
		return &ConsensusResult{
			Confirmed: false,
			TxID:      tx.ID,
		}, err
	}

	slog.Debug("block proposed", "tx_id", tx.ID, "round", proposal.Round, "proposer", proposer)

	// Collect votes from all validators.
	yesVotes := 0
	totalVotes := len(ce.validators)
	for _, v := range ce.validators {
		ballot := *proposal
		ballot.ValidatorID = v.ID
		vote, err := ce.ledger.Vote(&ballot)
		if err != nil {
			continue
		}
		if string(vote.Payload) == "yes" {
			yesVotes++
		}
	}

	slog.Debug("votes collected", "tx_id", tx.ID, "yes", yesVotes, "total", totalVotes)

	// Commit if majority.
	majority := totalVotes/2 + 1
	if yesVotes >= majority {
		commitMsg := &ConsensusMessage{
			Type:        MsgCommit,
			TxID:        tx.ID,
			ValidatorID: proposer,
			Round:       proposal.Round,
		}
		if err := ce.ledger.Commit(commitMsg); err != nil {
			ce.ledger.CleanupPending(tx.ID)
			return &ConsensusResult{
				Confirmed: false,
				Round:     proposal.Round,
				Votes:     yesVotes,
				TxID:      tx.ID,
			}, err
		}
		slog.Info("transaction committed", "tx_id", tx.ID, "round", proposal.Round, "votes", yesVotes)
		return &ConsensusResult{
			Confirmed: true,
			Round:     proposal.Round,
			Votes:     yesVotes,
			TxID:      tx.ID,
		}, nil
	}

	// Not enough votes — reject.
	slog.Warn("transaction rejected — insufficient votes", "tx_id", tx.ID, "yes", yesVotes, "needed", majority)
	ce.ledger.CleanupPending(tx.ID)
	return &ConsensusResult{
		Confirmed: false,
		Round:     proposal.Round,
		Votes:     yesVotes,
		TxID:      tx.ID,
	}, nil
}
