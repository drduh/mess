// Package tally counts string keys and ranks them.
package tally

import (
	"slices"
	"strings"
)

type Count struct {
	Key string `json:"key"`
	N   int    `json:"n"`
}

// SortTop orders counts by descending N, ties by name, and trims to n.
func SortTop(counts []Count, n int) []Count {
	slices.SortFunc(counts, func(a, b Count) int {
		if a.N != b.N {
			return b.N - a.N
		}
		return strings.Compare(a.Key, b.Key)
	})

	if len(counts) > n {
		counts = counts[:n]
	}

	return counts
}

// Counter tallies string keys.
type Counter map[string]int

// Add counts one more of key, creating it on first sight.
func (c Counter) Add(key string) { c[key]++ }

// Top returns the n most frequent keys.
func (c Counter) Top(n int) []Count {
	out := make([]Count, 0, len(c))
	for k, v := range c {
		out = append(out, Count{k, v})
	}

	return SortTop(out, n)
}

// Once returns the keys seen exactly one time, sorted.
func (c Counter) Once() []string {
	out := []string{}
	for k, v := range c {
		if v == 1 {
			out = append(out, k)
		}
	}

	slices.Sort(out)

	return out
}
