package main

import (
	"strings"
	"testing"

	"github.com/jurispath/jurispath/config"
	"github.com/jurispath/jurispath/internal/scion"
	"github.com/jurispath/jurispath/pkg/model"
)

func TestSelectPathExtractor_NonSCIONUsesMock(t *testing.T) {
	extractor := selectPathExtractor(&config.Config{})
	if _, ok := extractor.(*scion.MockPathExtractor); !ok {
		t.Fatalf("got %T, want *scion.MockPathExtractor", extractor)
	}
}

func TestSelectPathExtractor_SCIONRejectsAPIRawPath(t *testing.T) {
	extractor := selectPathExtractor(&config.Config{SCIONMode: true})
	if _, ok := extractor.(*scion.RejectingPathExtractor); !ok {
		t.Fatalf("got %T, want *scion.RejectingPathExtractor", extractor)
	}

	raw, err := scion.NewMockPath([]model.ASHop{
		{IA: "1-ff00:0:110", ISD: 1, AS: "ff00:0:110"},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = scion.BuildSCIONPath(extractor, raw)
	if err == nil {
		t.Fatal("expected SCION mode extractor to reject API raw_path")
	}
	if !strings.Contains(err.Error(), "authenticated SCION session metadata") {
		t.Fatalf("error %q does not explain required path evidence", err)
	}
}
