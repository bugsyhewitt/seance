package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type JSONFileStorage struct{ path string }

func NewJSONFileStorage(path string) *JSONFileStorage {
	return &JSONFileStorage{path: path}
}

func (s *JSONFileStorage) Load() (*State, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return New(), nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	if st.SeenCommits == nil {
		st.SeenCommits = make(map[string]time.Time)
	}
	if st.SeenFindings == nil {
		// Older state files predate cross-run finding dedup; initialise the map
		// so the engine can start suppressing re-leaks immediately.
		st.SeenFindings = make(map[string]time.Time)
	}
	return &st, nil
}

func (s *JSONFileStorage) Save(st *State) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
