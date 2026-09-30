package literal

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestIndexMatchesArbitraryBytes(t *testing.T) {
	words := []string{"he", "she", "hers", "a", "aa", "aaa", "中文", "İKΣς", "\x00\xff", "\xff", "\xfe\x80"}
	rng := rand.New(rand.NewSource(12))
	for len(words) < 200 {
		word := make([]byte, rng.Intn(20)+1)
		rng.Read(word)
		duplicate := false
		for _, w := range words {
			duplicate = duplicate || w == string(word)
		}
		if !duplicate {
			words = append(words, string(word))
		}
	}
	index := New(words)
	bits := make([]uint64, (len(words)+63)/64)
	for i := 0; i < 300; i++ {
		var body []byte
		for j := 0; j < 30; j++ {
			body = append(body, words[rng.Intn(len(words))]...)
			body = append(body, byte(rng.Intn(256)))
		}
		for _, useBytes := range []bool{true, false} {
			if useBytes {
				index.MatchBytes(body, bits)
			} else {
				index.Match(string(body), bits)
			}
			for id, word := range words {
				if got, want := bits[id/64]&(1<<uint(id%64)) != 0, bytes.Contains(body, []byte(word)); got != want {
					t.Fatalf("word=%q got=%t want=%t", word, got, want)
				}
			}
		}
	}
}
