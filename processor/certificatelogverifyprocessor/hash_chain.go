// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package certificatelogverifyprocessor

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"go.opentelemetry.io/collector/extension/xextension/storage"
	"go.opentelemetry.io/collector/pdata/plog"
)

const hashChainKeyPrefix = "hash_chain/"

type hashChainState struct {
	LastSequence    int64  `json:"last_sequence"`
	LastIntegrityHash string `json:"last_integrity_hash"`
}

type hashChainStore struct {
	client storage.Client
}

func newHashChainStore(client storage.Client) *hashChainStore {
	return &hashChainStore{client: client}
}

func (s *hashChainStore) validate(streamID string, lr plog.LogRecord) (string, error) {
	if streamID == "" {
		return "missing_stream_id", fmt.Errorf("audit.source.id is required for hash chain validation")
	}

	prevHash := strings.TrimSpace(attrString(lr, auditAttrPrevHash))
	seq, hasSeq := attrInt(lr, auditAttrSequenceNo)

	state, found, err := s.get(streamID)
	if err != nil {
		return "hash_chain_storage_error", err
	}

	if found {
		if prevHash != "" && !strings.EqualFold(prevHash, state.LastIntegrityHash) {
			return "prev_hash_mismatch", fmt.Errorf("audit.prev.hash does not match previous record integrity hash for stream %q", streamID)
		}
		if hasSeq && seq <= state.LastSequence {
			return "sequence_not_increasing", fmt.Errorf("audit.sequence.number %d must be greater than %d for stream %q", seq, state.LastSequence, streamID)
		}
	} else if prevHash != "" {
		return "unexpected_prev_hash", fmt.Errorf("audit.prev.hash present but no prior record for stream %q", streamID)
	}

	return reasonOK, nil
}

func (s *hashChainStore) commit(streamID string, lr plog.LogRecord, integrityHash string) error {
	state, found, err := s.get(streamID)
	if err != nil {
		return err
	}
	if !found {
		state = hashChainState{}
	}
	if seq, hasSeq := attrInt(lr, auditAttrSequenceNo); hasSeq {
		state.LastSequence = seq
	}
	state.LastIntegrityHash = integrityHash
	return s.set(streamID, state)
}

func (s *hashChainStore) get(streamID string) (hashChainState, bool, error) {
	data, err := s.client.Get(context.Background(), hashChainKeyPrefix+streamID)
	if err != nil {
		return hashChainState{}, false, err
	}
	if data == nil {
		return hashChainState{}, false, nil
	}
	var state hashChainState
	if err := json.Unmarshal(data, &state); err != nil {
		return hashChainState{}, false, fmt.Errorf("corrupt hash chain state for %q: %w", streamID, err)
	}
	return state, true, nil
}

func (s *hashChainStore) set(streamID string, state hashChainState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return s.client.Set(context.Background(), hashChainKeyPrefix+streamID, data)
}
