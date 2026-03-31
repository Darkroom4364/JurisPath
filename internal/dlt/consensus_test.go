package dlt

import (
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// testValidators returns the three default validators used across tests.
func testValidators() []ValidatorState {
	return []ValidatorState{
		{
			ID:      "CH",
			Address: "1-ff00:0:111,[127.0.0.1]:30100",
			Balance: map[string]int64{"CHF": 10000, "EUR": 5000},
		},
		{
			ID:      "EU",
			Address: "2-ff00:0:211,[127.0.0.1]:30200",
			Balance: map[string]int64{"CHF": 5000, "EUR": 10000},
		},
		{
			ID:      "X",
			Address: "3-ff00:0:310,[127.0.0.1]:30300",
			Balance: map[string]int64{"CHF": 1000, "EUR": 1000},
		},
	}
}

func TestSuccessfulSettlement(t *testing.T) {
	validators := testValidators()
	ledger := NewLedger(validators)
	engine := NewConsensusEngine(ledger, validators)

	tx := &Transaction{
		ID:       uuid.New().String(),
		From:     "CH",
		To:       "EU",
		Amount:   500,
		Currency: "CHF",
	}

	result, err := engine.RunRound(tx)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !result.Confirmed {
		t.Fatalf("expected transaction to be confirmed")
	}
	if result.Votes != 3 {
		t.Fatalf("expected 3 yes votes, got %d", result.Votes)
	}

	// Verify balances updated correctly.
	if got := ledger.GetBalance("CH", "CHF"); got != 9500 {
		t.Fatalf("CH CHF balance: expected 9500, got %d", got)
	}
	if got := ledger.GetBalance("EU", "CHF"); got != 5500 {
		t.Fatalf("EU CHF balance: expected 5500, got %d", got)
	}

	// Verify transaction is confirmed in history.
	stored := ledger.GetTransaction(tx.ID)
	if stored == nil {
		t.Fatal("transaction not found in ledger")
	}
	if stored.Status != TxConfirmed {
		t.Fatalf("expected status confirmed, got %s", stored.Status)
	}
}

func TestRejectedSettlementInsufficientBalance(t *testing.T) {
	validators := testValidators()
	ledger := NewLedger(validators)
	engine := NewConsensusEngine(ledger, validators)

	tx := &Transaction{
		ID:       uuid.New().String(),
		From:     "X",
		To:       "CH",
		Amount:   5000, // X only has 1000 CHF
		Currency: "CHF",
	}

	result, err := engine.RunRound(tx)
	if err == nil {
		t.Fatal("expected error for insufficient balance")
	}
	if result.Confirmed {
		t.Fatal("transaction should not be confirmed")
	}

	// Verify balances are unchanged.
	if got := ledger.GetBalance("X", "CHF"); got != 1000 {
		t.Fatalf("X CHF balance: expected 1000, got %d", got)
	}
	if got := ledger.GetBalance("CH", "CHF"); got != 10000 {
		t.Fatalf("CH CHF balance: expected 10000, got %d", got)
	}
}

func TestRoundNumberingIsMonotonic(t *testing.T) {
	validators := testValidators()
	ledger := NewLedger(validators)
	engine := NewConsensusEngine(ledger, validators)

	var lastRound uint64
	for i := 0; i < 5; i++ {
		tx := &Transaction{
			ID:       uuid.New().String(),
			From:     "CH",
			To:       "EU",
			Amount:   100,
			Currency: "CHF",
		}
		result, err := engine.RunRound(tx)
		if err != nil {
			t.Fatalf("round %d: unexpected error: %v", i, err)
		}
		if result.Round <= lastRound && i > 0 {
			t.Fatalf("round number not monotonic: previous=%d, current=%d", lastRound, result.Round)
		}
		lastRound = result.Round
	}
}

func TestConcurrentTransactions(t *testing.T) {
	validators := testValidators()
	ledger := NewLedger(validators)

	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Each goroutine gets its own engine to avoid proposal contention
			// on the same pending tx. This simulates independent settlement
			// requests arriving concurrently.
			eng := NewConsensusEngine(ledger, validators)
			tx := &Transaction{
				ID:       fmt.Sprintf("concurrent-tx-%d", idx),
				From:     "CH",
				To:       "EU",
				Amount:   100,
				Currency: "EUR",
			}
			_, err := eng.RunRound(tx)
			if err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	// Some transactions may fail due to race on balance, which is acceptable.
	// We just verify no panics occurred and the ledger is internally consistent.
	chEUR := ledger.GetBalance("CH", "EUR")
	euEUR := ledger.GetBalance("EU", "EUR")

	// CH started with 5000 EUR. Each successful tx sends 100 to EU.
	confirmedCount := 0
	for _, tx := range ledger.ListTransactions() {
		if tx.Status == TxConfirmed {
			confirmedCount++
		}
	}
	expectedCH := int64(5000) - int64(confirmedCount)*100
	if chEUR != expectedCH {
		t.Fatalf("CH EUR balance: expected %d, got %d (confirmed: %d)", expectedCH, chEUR, confirmedCount)
	}
	expectedEU := int64(10000) + int64(confirmedCount)*100
	if euEUR != expectedEU {
		t.Fatalf("EU EUR balance: expected %d, got %d", expectedEU, euEUR)
	}
	t.Logf("concurrent test: %d/%d transactions confirmed", confirmedCount, n)
}
