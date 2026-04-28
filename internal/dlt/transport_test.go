package dlt

import (
	"context"
	"testing"
	"time"
)

func TestLocalTransport_SendReceive(t *testing.T) {
	transports := NewLocalTransportSet([]string{"A", "B", "C"})
	ctx := context.Background()

	msg := &ConsensusMessage{
		Type:        MsgPropose,
		TxID:        "tx-1",
		ValidatorID: "A",
		Round:       1,
		Timestamp:   time.Now(),
	}

	if err := transports["A"].Send(ctx, "B", msg); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	got, pathInfo, err := transports["B"].Receive(ctx)
	if err != nil {
		t.Fatalf("receive failed: %v", err)
	}
	if pathInfo != nil {
		t.Fatal("expected nil PathInfo for local transport")
	}
	if got.TxID != "tx-1" || got.ValidatorID != "A" || got.Type != MsgPropose {
		t.Fatalf("unexpected message: %+v", got)
	}
}

func TestLocalTransport_Broadcast(t *testing.T) {
	transports := NewLocalTransportSet([]string{"A", "B", "C"})
	ctx := context.Background()

	msg := &ConsensusMessage{
		Type:        MsgPropose,
		TxID:        "tx-2",
		ValidatorID: "A",
		Round:       1,
	}

	if err := transports["A"].Broadcast(ctx, msg); err != nil {
		t.Fatalf("broadcast failed: %v", err)
	}

	// Both B and C should receive the message.
	for _, id := range []string{"B", "C"} {
		got, _, err := transports[id].Receive(ctx)
		if err != nil {
			t.Fatalf("receive from %s failed: %v", id, err)
		}
		if got.TxID != "tx-2" {
			t.Fatalf("wrong message at %s: %+v", id, got)
		}
	}
}

func TestLocalTransport_BlockValidator(t *testing.T) {
	transports := NewLocalTransportSet([]string{"A", "B"})
	ctx := context.Background()

	transports["A"].BlockValidator("B")

	msg := &ConsensusMessage{Type: MsgPropose, TxID: "tx-3", ValidatorID: "A"}
	err := transports["A"].Send(ctx, "B", msg)
	if err == nil {
		t.Fatal("expected error sending to blocked validator")
	}

	// Unblock and verify delivery works again.
	transports["A"].UnblockValidator("B")
	if err := transports["A"].Send(ctx, "B", msg); err != nil {
		t.Fatalf("send after unblock failed: %v", err)
	}
	got, _, err := transports["B"].Receive(ctx)
	if err != nil {
		t.Fatalf("receive after unblock failed: %v", err)
	}
	if got.TxID != "tx-3" {
		t.Fatalf("wrong message: %+v", got)
	}
}

func TestLocalTransport_ReceiveTimeout(t *testing.T) {
	transports := NewLocalTransportSet([]string{"A"})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, _, err := transports["A"].Receive(ctx)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestLocalTransport_SendUnknownValidator(t *testing.T) {
	transports := NewLocalTransportSet([]string{"A"})
	ctx := context.Background()

	msg := &ConsensusMessage{Type: MsgPropose, TxID: "tx-4"}
	err := transports["A"].Send(ctx, "UNKNOWN", msg)
	if err == nil {
		t.Fatal("expected error for unknown validator")
	}
}

func TestLocalTransport_MessageCopied(t *testing.T) {
	transports := NewLocalTransportSet([]string{"A", "B"})
	ctx := context.Background()

	msg := &ConsensusMessage{Type: MsgPropose, TxID: "tx-5", ValidatorID: "A", Payload: []byte("orig")}
	if err := transports["A"].Send(ctx, "B", msg); err != nil {
		t.Fatalf("send failed: %v", err)
	}

	// Mutate the original after sending.
	msg.TxID = "MUTATED"

	got, _, _ := transports["B"].Receive(ctx)
	if got.TxID != "tx-5" {
		t.Fatalf("message not deep-copied: got TxID %q", got.TxID)
	}
}
