package dlt

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ValidatorNode wraps a single validator's consensus engine, ledger, and
// transport. It listens for incoming proposals from other validators, votes
// on them, and can initiate settlements as proposer.
type ValidatorNode struct {
	ID           string
	Ledger       *Ledger
	Transport    ValidatorTransport
	VoteTimeout  time.Duration    // timeout waiting for remote votes (default 5s)
	Ready        chan struct{}     // closed by Run once the message loop starts

	validators []ValidatorState
	pendingMsgs map[string][]*ConsensusMessage // buffered messages by txID

	mu     sync.Mutex
	cancel context.CancelFunc
}

// NewValidatorNode creates a node for the given validator.
func NewValidatorNode(id string, validators []ValidatorState, transport ValidatorTransport) *ValidatorNode {
	return &ValidatorNode{
		ID:          id,
		Ledger:      NewLedger(validators),
		Transport:   transport,
		Ready:       make(chan struct{}),
		validators:  validators,
		pendingMsgs: make(map[string][]*ConsensusMessage),
	}
}

// Run starts the node's message loop, processing incoming consensus messages
// until the context is cancelled. It should be called in a goroutine.
func (n *ValidatorNode) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	n.mu.Lock()
	n.cancel = cancel
	n.mu.Unlock()

	slog.Info("validator node started", "id", n.ID)
	defer slog.Info("validator node stopped", "id", n.ID)

	close(n.Ready)

	for {
		msg, pathInfo, err := n.Transport.Receive(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			slog.Warn("receive error", "node", n.ID, "error", err)
			continue
		}

		switch msg.Type {
		case MsgPropose:
			n.handleProposal(ctx, msg, pathInfo)
		case MsgCommit:
			n.handleCommit(msg)
		default:
			slog.Debug("ignoring unexpected message type", "node", n.ID, "type", msg.Type)
		}
	}
}

// handleProposal processes an incoming proposal: submits the enclosed
// transaction to the local ledger, votes on it, and sends the vote
// back to the proposer.
func (n *ValidatorNode) handleProposal(ctx context.Context, proposal *ConsensusMessage, pathInfo *PathInfo) {
	_ = pathInfo // available for compliance checking on inter-validator paths

	// The proposal payload contains the serialized transaction so
	// remote validators can replicate it in their local ledger.
	if len(proposal.Payload) > 0 {
		var tx Transaction
		if err := json.Unmarshal(proposal.Payload, &tx); err != nil {
			slog.Warn("failed to unmarshal proposal tx", "node", n.ID, "error", err)
			return
		}
		if _, err := n.Ledger.SubmitTransactionIfAbsent(&tx); err != nil {
			slog.Warn("failed to submit proposal tx", "node", n.ID, "tx_id", tx.ID, "error", err)
			return
		}
	}

	ballot := *proposal
	ballot.ValidatorID = n.ID
	vote, err := n.Ledger.Vote(&ballot)
	if err != nil {
		slog.Warn("voting failed", "node", n.ID, "tx_id", proposal.TxID, "error", err)
		return
	}
	vote.ValidatorID = n.ID

	if err := n.Transport.Send(ctx, proposal.ValidatorID, vote); err != nil {
		slog.Warn("failed to send vote", "node", n.ID, "to", proposal.ValidatorID, "error", err)
	}
}

// handleCommit applies a committed transaction to the local ledger.
func (n *ValidatorNode) handleCommit(msg *ConsensusMessage) {
	if err := n.Ledger.Commit(msg); err != nil {
		slog.Warn("commit failed", "node", n.ID, "tx_id", msg.TxID, "error", err)
	}
}

// ProposeSettlement initiates a consensus round for a new transaction.
// The node acts as proposer: broadcasts the proposal, collects votes
// with a timeout, and commits or rejects.
func (n *ValidatorNode) ProposeSettlement(ctx context.Context, tx *Transaction) (*ConsensusResult, error) {
	// Submit to local ledger.
	if err := n.Ledger.SubmitTransaction(tx); err != nil {
		return &ConsensusResult{Confirmed: false, TxID: tx.ID}, err
	}

	// Create proposal.
	proposal, err := n.Ledger.ProposeBlock(n.ID)
	if err != nil {
		n.Ledger.CleanupPending(tx.ID)
		return &ConsensusResult{Confirmed: false, TxID: tx.ID}, err
	}

	// Attach the transaction to the proposal so remote validators can
	// replicate it in their local ledger before voting.
	txData, err := json.Marshal(tx)
	if err != nil {
		n.Ledger.CleanupPending(tx.ID)
		return &ConsensusResult{Confirmed: false, TxID: tx.ID}, fmt.Errorf("marshaling tx: %w", err)
	}
	proposal.Payload = txData

	slog.Debug("proposing settlement", "node", n.ID, "tx_id", tx.ID, "round", proposal.Round)

	// Broadcast proposal to all other validators.
	if err := n.Transport.Broadcast(ctx, proposal); err != nil {
		slog.Warn("broadcast partially failed", "node", n.ID, "error", err)
	}

	// Count our own vote.
	selfBallot := *proposal
	selfBallot.ValidatorID = n.ID
	selfVote, err := n.Ledger.Vote(&selfBallot)
	if err != nil {
		n.Ledger.CleanupPending(tx.ID)
		return &ConsensusResult{Confirmed: false, TxID: tx.ID, Round: proposal.Round}, err
	}

	yesVotes := 0
	if string(selfVote.Payload) == "yes" {
		yesVotes++
	}

	// Collect votes from remote validators with timeout.
	totalVotes := len(n.validators)
	votesNeeded := totalVotes - 1 // already have self vote
	voteTimeout := n.VoteTimeout
	if voteTimeout == 0 {
		voteTimeout = 5 * time.Second
	}
	voteCtx, voteCancel := context.WithTimeout(ctx, voteTimeout)
	defer voteCancel()

	collected := 0

	// Drain any votes for this tx that arrived while we were busy.
	if pending, ok := n.pendingMsgs[tx.ID]; ok {
		for _, pm := range pending {
			if pm.Type == MsgVote {
				collected++
				if string(pm.Payload) == "yes" {
					yesVotes++
				}
			}
		}
		delete(n.pendingMsgs, tx.ID)
	}

	for collected < votesNeeded {
		msg, _, err := n.Transport.Receive(voteCtx)
		if err != nil {
			break // timeout or context cancelled
		}
		if msg.Type != MsgVote || msg.TxID != tx.ID {
			// Buffer for later processing instead of dropping.
			n.pendingMsgs[msg.TxID] = append(n.pendingMsgs[msg.TxID], msg)
			continue
		}
		collected++
		if string(msg.Payload) == "yes" {
			yesVotes++
		}
	}

	slog.Debug("votes collected", "node", n.ID, "tx_id", tx.ID, "yes", yesVotes, "total", totalVotes)

	majority := totalVotes/2 + 1
	if yesVotes >= majority {
		commitMsg := &ConsensusMessage{
			Type:        MsgCommit,
			TxID:        tx.ID,
			ValidatorID: n.ID,
			Round:       proposal.Round,
			Timestamp:   time.Now(),
		}

		// Commit locally.
		if err := n.Ledger.Commit(commitMsg); err != nil {
			n.Ledger.CleanupPending(tx.ID)
			return &ConsensusResult{
				Confirmed: false,
				Round:     proposal.Round,
				Votes:     yesVotes,
				TxID:      tx.ID,
			}, err
		}

		// Broadcast commit to all peers.
		if err := n.Transport.Broadcast(ctx, commitMsg); err != nil {
			slog.Warn("commit broadcast partially failed", "node", n.ID, "error", err)
		}

		slog.Info("transaction committed", "node", n.ID, "tx_id", tx.ID, "round", proposal.Round, "votes", yesVotes)
		return &ConsensusResult{
			Confirmed: true,
			Round:     proposal.Round,
			Votes:     yesVotes,
			TxID:      tx.ID,
		}, nil
	}

	slog.Warn("transaction rejected — insufficient votes",
		"node", n.ID, "tx_id", tx.ID, "yes", yesVotes, "needed", majority)
	n.Ledger.CleanupPending(tx.ID)
	return &ConsensusResult{
		Confirmed: false,
		Round:     proposal.Round,
		Votes:     yesVotes,
		TxID:      tx.ID,
	}, fmt.Errorf("insufficient votes: got %d, need %d", yesVotes, majority)
}

// Stop gracefully shuts down the node.
func (n *ValidatorNode) Stop() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.cancel != nil {
		n.cancel()
	}
}
