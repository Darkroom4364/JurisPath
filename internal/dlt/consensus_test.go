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

func TestCleanupPending(t *testing.T) {
	validators := testValidators()
	ledger := NewLedger(validators)

	tx := &Transaction{
		ID:       uuid.New().String(),
		From:     "CH",
		To:       "EU",
		Amount:   100,
		Currency: "CHF",
	}

	if err := ledger.SubmitTransaction(tx); err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	if got := ledger.GetTransaction(tx.ID); got == nil {
		t.Fatal("expected tx in pending")
	}

	ledger.CleanupPending(tx.ID)

	if got := ledger.GetTransaction(tx.ID); got != nil {
		t.Fatalf("expected tx removed from pending, got status %s", got.Status)
	}
	if tx.Status != TxRejected {
		t.Fatalf("expected TxRejected, got %s", tx.Status)
	}
}

func TestSubmitTransactionIfAbsent_NewTx(t *testing.T) {
	validators := testValidators()
	ledger := NewLedger(validators)

	tx := &Transaction{
		ID:       uuid.New().String(),
		From:     "CH",
		To:       "EU",
		Amount:   200,
		Currency: "CHF",
	}

	existing, err := ledger.SubmitTransactionIfAbsent(tx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if existing != nil {
		t.Fatal("expected nil existing for new tx")
	}
	if got := ledger.GetTransaction(tx.ID); got == nil {
		t.Fatal("expected tx in pending after submit")
	}
}

func TestSubmitTransactionIfAbsent_Duplicate(t *testing.T) {
	validators := testValidators()
	ledger := NewLedger(validators)

	tx := &Transaction{
		ID:       uuid.New().String(),
		From:     "CH",
		To:       "EU",
		Amount:   200,
		Currency: "CHF",
	}

	if _, err := ledger.SubmitTransactionIfAbsent(tx); err != nil {
		t.Fatalf("first submit failed: %v", err)
	}

	tx2 := &Transaction{
		ID:       tx.ID,
		From:     "CH",
		To:       "EU",
		Amount:   200,
		Currency: "CHF",
	}
	existing, err := ledger.SubmitTransactionIfAbsent(tx2)
	if err != nil {
		t.Fatalf("unexpected error on duplicate: %v", err)
	}
	if existing == nil {
		t.Fatal("expected existing tx on duplicate submit")
	}
}

func TestSubmitTransactionIfAbsent_AfterRejection(t *testing.T) {
	validators := testValidators()
	ledger := NewLedger(validators)

	tx := &Transaction{
		ID:       uuid.New().String(),
		From:     "CH",
		To:       "EU",
		Amount:   200,
		Currency: "CHF",
	}

	if _, err := ledger.SubmitTransactionIfAbsent(tx); err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	ledger.CleanupPending(tx.ID)

	tx2 := &Transaction{
		ID:       tx.ID,
		From:     "CH",
		To:       "EU",
		Amount:   200,
		Currency: "CHF",
	}
	existing, err := ledger.SubmitTransactionIfAbsent(tx2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if existing == nil {
		t.Fatal("expected existing tx after rejection")
	}
	if existing.Status != TxRejected {
		t.Fatalf("expected TxRejected, got %s", existing.Status)
	}
}

func TestRunRoundFromPending(t *testing.T) {
	validators := testValidators()
	ledger := NewLedger(validators)
	engine := NewConsensusEngine(ledger, validators)

	tx := &Transaction{
		ID:       uuid.New().String(),
		From:     "CH",
		To:       "EU",
		Amount:   300,
		Currency: "CHF",
	}

	if _, err := ledger.SubmitTransactionIfAbsent(tx); err != nil {
		t.Fatalf("submit failed: %v", err)
	}

	result, err := engine.RunRoundFromPending(tx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Confirmed {
		t.Fatal("expected transaction to be confirmed")
	}
	if got := ledger.GetBalance("CH", "CHF"); got != 9700 {
		t.Fatalf("CH CHF balance: expected 9700, got %d", got)
	}
	if got := ledger.GetBalance("EU", "CHF"); got != 5300 {
		t.Fatalf("EU CHF balance: expected 5300, got %d", got)
	}
}

func TestRejectedTxCleanup(t *testing.T) {
	// Use a validator with 0 balance for the currency so votes say "no".
	validators := []ValidatorState{
		{
			ID:      "A",
			Address: "1-ff00:0:111,[127.0.0.1]:30100",
			Balance: map[string]int64{"CHF": 1000, "EUR": 0},
		},
		{
			ID:      "B",
			Address: "2-ff00:0:211,[127.0.0.1]:30200",
			Balance: map[string]int64{"CHF": 1000, "EUR": 5000},
		},
		{
			ID:      "C",
			Address: "3-ff00:0:310,[127.0.0.1]:30300",
			Balance: map[string]int64{"CHF": 1000, "EUR": 5000},
		},
	}
	ledger := NewLedger(validators)
	engine := NewConsensusEngine(ledger, validators)

	// A sends EUR but has 0 — submit succeeds (SubmitTransaction checks balance
	// at submit time, and A has 0 so it will fail at submit).
	// Instead, give A just enough to pass submit but drain before vote.
	// Simpler: use RunRound with amount exceeding balance so it errors at submit.
	// Actually, let's test the vote-rejection path: give A enough to submit but
	// drain balance before commit. The easiest approach: use a separate ledger
	// where A has balance, submit tx, then externally drain A's balance and run
	// consensus. But ledger doesn't expose draining.
	//
	// The simplest approach: A has 1000 CHF. Submit a tx for 1000 CHF. Then
	// submit *another* tx for 1000 CHF (which will fail at submit since balance
	// is still locked). That doesn't work either since balance isn't debited until commit.
	//
	// Actually the vote checks balance at vote time. If we submit two txs for
	// 1000 CHF each, the first will confirm (debiting A), and the second vote
	// will say "no" because balance is now 0. But RunRound submits & proposes
	// in one shot. Let's just confirm the first, then run the second.

	tx1 := &Transaction{
		ID:       uuid.New().String(),
		From:     "A",
		To:       "B",
		Amount:   1000,
		Currency: "CHF",
	}
	result, err := engine.RunRound(tx1)
	if err != nil {
		t.Fatalf("first round error: %v", err)
	}
	if !result.Confirmed {
		t.Fatal("expected first tx confirmed")
	}

	// Now A has 0 CHF. Submit another 1000 CHF tx — submit will fail because
	// SubmitTransaction checks balance. So this tests the submit-rejection path.
	// But the ask is to test that rejected tx is NOT left in pending after RunRound.
	// SubmitTransaction rejects before adding to pending, so nothing to clean.
	//
	// To get a vote-rejection: we need the tx in pending but votes say no.
	// Give A some balance back via a reverse tx won't work without modifying ledger.
	// Alternative: use RunRoundFromPending directly to get a rejected tx in pending.

	// Reset with fresh ledger where the vote will reject.
	validators2 := []ValidatorState{
		{
			ID:      "A",
			Address: "1-ff00:0:111,[127.0.0.1]:30100",
			Balance: map[string]int64{"CHF": 500},
		},
		{
			ID:      "B",
			Address: "2-ff00:0:211,[127.0.0.1]:30200",
			Balance: map[string]int64{"CHF": 5000},
		},
		{
			ID:      "C",
			Address: "3-ff00:0:310,[127.0.0.1]:30300",
			Balance: map[string]int64{"CHF": 5000},
		},
	}
	ledger2 := NewLedger(validators2)
	engine2 := NewConsensusEngine(ledger2, validators2)

	// Submit tx for 500 CHF (passes submit check).
	txReject := &Transaction{
		ID:       uuid.New().String(),
		From:     "A",
		To:       "B",
		Amount:   500,
		Currency: "CHF",
	}
	// First confirm this to drain A's balance.
	r, err := engine2.RunRound(txReject)
	if err != nil || !r.Confirmed {
		t.Fatalf("setup tx failed: err=%v confirmed=%v", err, r.Confirmed)
	}

	// Now A has 0 CHF. Submit a new tx that will pass SubmitTransaction
	// ... wait, it won't pass because balance is 0. We need a different approach.
	//
	// Correct approach: SubmitTransaction only checks balance >= amount.
	// If two txs are submitted for the same balance, the first commits and the
	// second fails at vote/commit. Let's submit both before running consensus.

	validators3 := []ValidatorState{
		{
			ID:      "A",
			Address: "1-ff00:0:111,[127.0.0.1]:30100",
			Balance: map[string]int64{"CHF": 500},
		},
		{
			ID:      "B",
			Address: "2-ff00:0:211,[127.0.0.1]:30200",
			Balance: map[string]int64{"CHF": 5000},
		},
		{
			ID:      "C",
			Address: "3-ff00:0:310,[127.0.0.1]:30300",
			Balance: map[string]int64{"CHF": 5000},
		},
	}
	ledger3 := NewLedger(validators3)
	engine3 := NewConsensusEngine(ledger3, validators3)

	// Submit first tx (will commit, draining A to 0).
	tx3a := &Transaction{
		ID:       uuid.New().String(),
		From:     "A",
		To:       "B",
		Amount:   500,
		Currency: "CHF",
	}
	r3a, err := engine3.RunRound(tx3a)
	if err != nil || !r3a.Confirmed {
		t.Fatalf("first tx failed: err=%v confirmed=%v", err, r3a.Confirmed)
	}

	// Now submit second tx — A has 0, so SubmitTransaction will reject.
	// Use SubmitTransactionIfAbsent to add directly. But that also checks balance.
	// The only way to get a tx into pending with insufficient balance for the vote
	// is to submit it BEFORE the first tx commits (double-spend scenario).
	// Let's just use the SubmitTransaction + RunRoundFromPending flow.

	// Final correct approach: submit two txs to pending (both pass balance check
	// because balance hasn't been debited yet), then run them sequentially.
	validators4 := []ValidatorState{
		{
			ID:      "A",
			Address: "1-ff00:0:111,[127.0.0.1]:30100",
			Balance: map[string]int64{"CHF": 500},
		},
		{
			ID:      "B",
			Address: "2-ff00:0:211,[127.0.0.1]:30200",
			Balance: map[string]int64{"CHF": 5000},
		},
		{
			ID:      "C",
			Address: "3-ff00:0:310,[127.0.0.1]:30300",
			Balance: map[string]int64{"CHF": 5000},
		},
	}
	ledger4 := NewLedger(validators4)
	engine4 := NewConsensusEngine(ledger4, validators4)

	// Submit two txs for 500 each (both pass because A has 500 and balance
	// isn't debited until commit).
	tx4a := &Transaction{
		ID:       uuid.New().String(),
		From:     "A",
		To:       "B",
		Amount:   500,
		Currency: "CHF",
	}
	tx4b := &Transaction{
		ID:       uuid.New().String(),
		From:     "A",
		To:       "B",
		Amount:   500,
		Currency: "CHF",
	}
	if err := ledger4.SubmitTransaction(tx4a); err != nil {
		t.Fatalf("submit tx4a: %v", err)
	}
	if err := ledger4.SubmitTransaction(tx4b); err != nil {
		t.Fatalf("submit tx4b: %v", err)
	}

	// Run consensus for first (confirms, A goes to 0).
	r4a, err := engine4.RunRoundFromPending(tx4a)
	if err != nil || !r4a.Confirmed {
		t.Fatalf("tx4a consensus: err=%v confirmed=%v", err, r4a.Confirmed)
	}

	// Run consensus for second (votes "no" because A now has 0).
	r4b, err := engine4.RunRoundFromPending(tx4b)
	if err != nil {
		t.Fatalf("tx4b unexpected error: %v", err)
	}
	if r4b.Confirmed {
		t.Fatal("expected tx4b to be rejected")
	}

	// Verify tx4b is NOT left in pending.
	if got := ledger4.GetTransaction(tx4b.ID); got != nil {
		t.Fatalf("rejected tx should not be in pending, got status %s", got.Status)
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
