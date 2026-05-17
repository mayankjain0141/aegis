package bloom

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"

	"github.com/cespare/xxhash/v2"
)

// Filter is a simple Bloom filter for fast-path cache lookups.
type Filter struct {
	data []uint64
	k    int // number of hash functions
	m    int // bit array size in bits
}

// New creates a Bloom filter sized for expectedItems with falsePositiveRate probability.
func New(expectedItems int, falsePositiveRate float64) *Filter {
	if expectedItems <= 0 {
		expectedItems = 100
	}
	if falsePositiveRate <= 0 || falsePositiveRate >= 1 {
		falsePositiveRate = 0.01
	}

	m := optimalM(expectedItems, falsePositiveRate)
	k := optimalK(m, expectedItems)

	words := (m + 63) / 64
	return &Filter{
		data: make([]uint64, words),
		k:    k,
		m:    m,
	}
}

// Add inserts a key into the filter.
func (f *Filter) Add(key string) {
	h1, h2 := doubleHash(key)
	for i := 0; i < f.k; i++ {
		bit := (h1 + uint64(i)*h2) % uint64(f.m)
		f.data[bit/64] |= 1 << (bit % 64)
	}
}

// Contains returns true if the key was probably added (false positives possible).
func (f *Filter) Contains(key string) bool {
	if f == nil || len(f.data) == 0 {
		return false
	}
	h1, h2 := doubleHash(key)
	for i := 0; i < f.k; i++ {
		bit := (h1 + uint64(i)*h2) % uint64(f.m)
		if f.data[bit/64]&(1<<(bit%64)) == 0 {
			return false
		}
	}
	return true
}

// Len returns the number of bits set (approximate fill level).
func (f *Filter) Len() int {
	count := 0
	for _, word := range f.data {
		count += popcount(word)
	}
	return count
}

// CanonicalKey builds the bloom filter lookup key for a tool call.
// Format: "toolname:sorted-json-args" — canonical so arg key order doesn't matter.
func CanonicalKey(tool string, args map[string]any) string {
	if len(args) == 0 {
		return tool + ":"
	}
	// Sort keys for determinism
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	ordered := make(map[string]any, len(args))
	for _, k := range keys {
		ordered[k] = args[k]
	}
	// Drop large values (file content etc.) to keep key short
	for k, v := range ordered {
		if s, ok := v.(string); ok && len(s) > 200 {
			ordered[k] = s[:50] + "…"
		}
	}
	b, err := json.Marshal(ordered)
	if err != nil {
		return fmt.Sprintf("%s:%v", tool, args)
	}
	return tool + ":" + string(b)
}

// CanonicalKeyFromJSON builds a canonical key from tool + raw JSON args string.
func CanonicalKeyFromJSON(tool string, argsJSON string) string {
	var args map[string]any
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return tool + ":" + argsJSON
	}
	return CanonicalKey(tool, args)
}

// doubleHash returns two independent hashes for double-hashing technique.
func doubleHash(key string) (uint64, uint64) {
	b := []byte(key)
	h1 := xxhash.Sum64(b)
	// Second hash: rotate seed
	h2 := xxhash.Sum64(append(b, 0xff))
	if h2 == 0 {
		h2 = 1 // prevent h2=0 which would make all probes the same
	}
	return h1, h2
}

func optimalM(n int, p float64) int {
	// m = -n * ln(p) / (ln(2)^2)
	m := int(math.Ceil(-float64(n) * math.Log(p) / (math.Log(2) * math.Log(2))))
	if m < 64 {
		m = 64
	}
	return m
}

func optimalK(m, n int) int {
	// k = (m/n) * ln(2)
	k := int(math.Round(float64(m) / float64(n) * math.Log(2)))
	if k < 1 {
		k = 1
	}
	if k > 20 {
		k = 20
	}
	return k
}

func popcount(x uint64) int {
	count := 0
	for x != 0 {
		count += int(x & 1)
		x >>= 1
	}
	return count
}

// Export returns the internal state for persistence.
func (f *Filter) Export() (data []uint64, m, k int) {
	if f == nil {
		return nil, 0, 0
	}
	d := make([]uint64, len(f.data))
	copy(d, f.data)
	return d, f.m, f.k
}

// Import restores bloom filter state from persisted data.
// Returns an empty filter if the parameters are inconsistent, preventing panics
// from out-of-bounds bit indexing on corrupted persistence data.
func Import(data []uint64, m, k int) *Filter {
	if m <= 0 || k <= 0 {
		return New(100, 0.01)
	}
	expected := (m + 63) / 64
	if len(data) != expected {
		return New(100, 0.01) // corrupted — return empty rather than panic
	}
	f := &Filter{
		data: make([]uint64, len(data)),
		m:    m,
		k:    k,
	}
	copy(f.data, data)
	return f
}
