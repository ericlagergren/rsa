package rsa

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func u64(v int) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	return b
}

func TestExcludes(t *testing.T) {
	g, err := Generate(rand.Reader, 64)
	if err != nil {
		t.Fatal(err)
	}
	const (
		N = 10
	)
	for i := 0; i < N; i++ {
		v := u64(i)
		if !g.Excludes(v) {
			t.Fatalf("#%d: expected true", i)
		}
		g.Add(v)
		if g.Excludes(v) {
			t.Fatalf("#%d: expected false", i)
		}
	}
}

func TestXXX(t *testing.T) {
	g, err := Generate(rand.Reader, 64)
	if err != nil {
		t.Fatal(err)
	}
	const (
		N = 100
	)
	for i := 0; i < N; i++ {
		g.Add(u64(i))
	}
	for i := 0; i < N; i++ {
		if !g.Includes(u64(i)) {
			t.Fatalf("#%d: expected true", i)
		}
	}
}

func TestIncludes(t *testing.T) {
	g, err := Generate(rand.Reader, 64)
	if err != nil {
		t.Fatal(err)
	}
	const (
		N = 10
	)
	for i := 0; i < N; i++ {
		v := u64(i)
		if g.Includes(v) {
			t.Fatalf("#%d: expected false", i)
		}
		g.Add(v)
		if !g.Includes(v) {
			t.Fatalf("#%d: expected true", i)
		}
	}
}

func TestVerify(t *testing.T) {
	g, err := Generate(rand.Reader, 64)
	if err != nil {
		t.Fatal(err)
	}

	const (
		N = 100
	)
	wits := make([]Witness, N)
	for i := range wits {
		wits[i] = g.Add(u64(i))
		if !g.Verify(wits[i]) {
			t.Fatalf("#%d: expected true", i)
		}
	}

	for i := range wits {
		if !g.Includes(u64(i)) {
			t.Fatalf("#%d: expected true", i)
		}
	}

	// The existing witnesses need to be updated.
	for i, w := range wits[:len(wits)-1] {
		if g.Verify(w) {
			t.Fatalf("#%d: expected false", i)
		}
	}

	g.UpdateAll(wits)

	// Now they're all correct.
	for i, w := range wits {
		if !g.Verify(w) {
			t.Fatalf("#%d: expected true", i)
		}
	}

	// Test deletion.
	updated := make([]Change, 0, len(wits))
	for i, w := range wits {
		for _, u := range updated {
			w = g.Update(u, w)
		}
		updated = append(updated, g.Delete(u64(i)))
		if g.Verify(w) {
			t.Fatalf("#%d: expected false", i)
		}
	}
}
