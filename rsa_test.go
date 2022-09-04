package rsa

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"
)

func u64(v int) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	return b
}

func TestBitlen(t *testing.T) {
	const N = 10_000

	y := new(big.Int)
	x := big.NewInt(1)
	for i := 0; i < N; i++ {
		d := hash(u64(i))
		x.Mul(x, y.SetBytes(d[:]))
	}
	fmt.Println(x.BitLen() / 8)
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

func TestExcludes(t *testing.T) {
	g, err := Generate(rand.Reader, 64)
	if err != nil {
		t.Fatal(err)
	}
	const (
		N = 10
	)
	g.Add(u64(N + 1))
	g.Add(u64(N + 2))
	for i := 0; i < N; i++ {
		if !g.Excludes(u64(i)) {
			t.Fatalf("#%d: expected true", i)
		}
	}
}
