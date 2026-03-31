package dlt

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
		return &ConsensusResult{
			Confirmed: true,
			Round:     proposal.Round,
			Votes:     yesVotes,
			TxID:      tx.ID,
		}, nil
	}

	// Not enough votes — reject the transaction.
	tx.Status = TxRejected
	return &ConsensusResult{
		Confirmed: false,
		Round:     proposal.Round,
		Votes:     yesVotes,
		TxID:      tx.ID,
	}, nil
}
