package dlt

import "log/slog"

// ConsensusEngine orchestrates a simple 2-phase consensus protocol
// (propose -> vote -> commit) across a set of validators. Currently runs
// locally in a single process; the SCION networking layer will be plugged
// in separately.
type ConsensusEngine struct {
	ledger       *Ledger
	validators   []ValidatorState
	currentRound uint64
}

// NewConsensusEngine creates a consensus engine backed by the given ledger.
func NewConsensusEngine(ledger *Ledger, validators []ValidatorState) *ConsensusEngine {
	return &ConsensusEngine{
		ledger:     ledger,
		validators: validators,
	}
}

// RunRound orchestrates a full consensus round for a single transaction:
//  1. Submit the transaction to the ledger's pending pool.
//  2. The first validator proposes a block.
//  3. All validators vote on the proposal.
//  4. If a majority votes yes, the transaction is committed.
func (ce *ConsensusEngine) RunRound(tx *Transaction) (*ConsensusResult, error) {
	slog.Debug("starting consensus round", "tx_id", tx.ID, "from", tx.From, "to", tx.To, "amount", tx.Amount, "currency", tx.Currency)

	// Step 1: submit to pending pool.
	if err := ce.ledger.SubmitTransaction(tx); err != nil {
		return &ConsensusResult{
			Confirmed: false,
			TxID:      tx.ID,
		}, err
	}

	// Step 2: first validator proposes.
	proposer := ce.validators[0].ID
	proposal, err := ce.ledger.ProposeBlock(proposer)
	if err != nil {
		return &ConsensusResult{
			Confirmed: false,
			TxID:      tx.ID,
		}, err
	}

	ce.currentRound = proposal.Round
	slog.Debug("block proposed", "tx_id", tx.ID, "round", proposal.Round, "proposer", proposer)

	// Step 3: collect votes from all validators.
	yesVotes := 0
	totalVotes := len(ce.validators)
	for _, v := range ce.validators {
		vote, err := ce.ledger.Vote(proposal)
		if err != nil {
			continue
		}
		_ = v // vote is cast on behalf of each validator
		if string(vote.Payload) == "yes" {
			yesVotes++
		}
	}

	slog.Debug("votes collected", "tx_id", tx.ID, "yes", yesVotes, "total", totalVotes)

	// Step 4: commit if majority.
	majority := totalVotes/2 + 1
	if yesVotes >= majority {
		commitMsg := &ConsensusMessage{
			Type:        MsgCommit,
			TxID:        tx.ID,
			ValidatorID: proposer,
			Round:       proposal.Round,
		}
		if err := ce.ledger.Commit(commitMsg); err != nil {
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

	// Not enough votes — reject the transaction.
	slog.Warn("transaction rejected — insufficient votes", "tx_id", tx.ID, "yes", yesVotes, "needed", majority)
	tx.Status = TxRejected
	return &ConsensusResult{
		Confirmed: false,
		Round:     proposal.Round,
		Votes:     yesVotes,
		TxID:      tx.ID,
	}, nil
}
