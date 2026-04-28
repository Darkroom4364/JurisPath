package dlt

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// startNodes creates and starts validator nodes connected via LocalTransport.
func startNodes(t *testing.T, validators []ValidatorState) (map[string]*ValidatorNode, map[string]*LocalTransport) {
	t.Helper()

	ids := make([]string, len(validators))
	for i, v := range validators {
		ids[i] = v.ID
	}
	transports := NewLocalTransportSet(ids)

	nodes := make(map[string]*ValidatorNode, len(validators))
	for _, v := range validators {
		node := NewValidatorNode(v.ID, validators, transports[v.ID])
		node.VoteTimeout = 200 * time.Millisecond // fast timeout for tests
		nodes[v.ID] = node
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Start all non-proposer nodes (proposer drives the round directly).
	for id, node := range nodes {
		if id == ids[0] {
			continue // proposer doesn't need the Run loop
		}
		go node.Run(ctx) //nolint:errcheck
	}

	// Brief pause for goroutines to start receiving.
	time.Sleep(10 * time.Millisecond)

	return nodes, transports
}

func TestNodeConsensus_AllValidators(t *testing.T) {
	validators := testValidators()
	nodes, _ := startNodes(t, validators)

	proposer := nodes["CH"]
	tx := &Transaction{
		ID:       uuid.New().String(),
		From:     "CH",
		To:       "EU",
		Amount:   500,
		Currency: "CHF",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := proposer.ProposeSettlement(ctx, tx)
	if err != nil {
		t.Fatalf("settlement failed: %v", err)
	}
	if !result.Confirmed {
		t.Fatal("expected transaction to be confirmed")
	}
	if result.Votes != 3 {
		t.Fatalf("expected 3 yes votes, got %d", result.Votes)
	}

	// Verify proposer's ledger was updated.
	if got := proposer.Ledger.GetBalance("CH", "CHF"); got != 9500 {
		t.Fatalf("CH CHF balance: expected 9500, got %d", got)
	}
}

func TestNodeConsensus_OneBlockedStillCommits(t *testing.T) {
	validators := testValidators()
	nodes, transports := startNodes(t, validators)

	// Block validator X — proposer can't reach it.
	transports["CH"].BlockValidator("X")

	proposer := nodes["CH"]
	tx := &Transaction{
		ID:       uuid.New().String(),
		From:     "CH",
		To:       "EU",
		Amount:   200,
		Currency: "CHF",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := proposer.ProposeSettlement(ctx, tx)
	if err != nil {
		t.Fatalf("settlement failed: %v", err)
	}
	if !result.Confirmed {
		t.Fatal("expected transaction to be confirmed with 2/3 majority")
	}
	if result.Votes < 2 {
		t.Fatalf("expected at least 2 votes, got %d", result.Votes)
	}
}

func TestNodeConsensus_TwoBlockedRejects(t *testing.T) {
	validators := testValidators()
	nodes, transports := startNodes(t, validators)

	// Block both EU and X — only proposer's own vote remains (1/3).
	transports["CH"].BlockValidator("EU")
	transports["CH"].BlockValidator("X")

	proposer := nodes["CH"]
	tx := &Transaction{
		ID:       uuid.New().String(),
		From:     "CH",
		To:       "EU",
		Amount:   100,
		Currency: "CHF",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := proposer.ProposeSettlement(ctx, tx)
	if err == nil {
		t.Fatal("expected error for insufficient votes")
	}
	if result.Confirmed {
		t.Fatal("expected transaction to be rejected with 1/3 minority")
	}
	if result.Votes != 1 {
		t.Fatalf("expected 1 vote (self only), got %d", result.Votes)
	}
}

func TestNodeConsensus_InsufficientBalance(t *testing.T) {
	validators := testValidators()
	nodes, _ := startNodes(t, validators)

	proposer := nodes["CH"]
	tx := &Transaction{
		ID:       uuid.New().String(),
		From:     "CH",
		To:       "EU",
		Amount:   999999, // way more than CH has
		Currency: "CHF",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := proposer.ProposeSettlement(ctx, tx)
	if err == nil {
		t.Fatal("expected error for insufficient balance")
	}
}
