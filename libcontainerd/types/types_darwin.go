// +build darwin

package types

import "time"

// Summary is irrelvant for the current port of dockerd
type Summary struct{}

// Stats is irrelavant for the current port of dockerd
type Stats struct{}

// Resources is irrelavant for the current port of dockerd
type Resources struct{}

// InterfaceToStats returna a stats object, but here it returns empty.
func InterfaceToStats(read time.Time, v interface{}) *Stats {
	return &Stats{}
}

// Checkpoints contain the details of a checkpoint, irrelavant for the current port of dockerd
type Checkpoints struct{}
