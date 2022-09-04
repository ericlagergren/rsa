package rsa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math"
	"math/big"
)

var (
	one = big.NewInt(1)
	g   = big.NewInt(3)
)

type Change interface {
	internal()
}

type Update struct {
	x *big.Int // H(v)
	n *big.Int // N = p*q
	a *big.Int // g^u (after x)
}

func (Update) internal() {}

type Witness struct {
	x *big.Int // H(v)
	w *big.Int // witness (g^u before x)
	n *big.Int // N = p*q
	c *big.Int // g^u (after x)
}

func (Witness) internal() {}

type Accumulator struct {
	n *big.Int // N = p*q
	t *big.Int // 𝜑(N) = (p-1)*(q-1)
	c *big.Int // g^u
	u *big.Int // ∏x_i mod 𝜑(N)
}

func Generate(rng io.Reader, bits int) (*Accumulator, error) {
	for {
		p, err := rand.Prime(rng, bits)
		if err != nil {
			return nil, err
		}
		q, err := rand.Prime(rng, bits)
		if err != nil {
			return nil, err
		}

		pm1 := new(big.Int).Sub(p, one)
		qm1 := new(big.Int).Sub(q, one)
		t := new(big.Int).Mul(pm1, qm1)

		if gcd(nil, nil, g, t) {
			return &Accumulator{
				n: new(big.Int).Mul(p, q),
				t: t,
				c: new(big.Int).Set(g),
				u: big.NewInt(1),
			}, nil
		}
	}
}

// Add inserts v into the accumulator and returns the witness
// proving membership.
//
// The results are undefined if v is already a member of the
// accumulator.
func (z *Accumulator) Add(v []byte) Witness {
	x := hashToPrime(v)
	w := new(big.Int).Set(z.c)
	z.u.Mul(z.u, x)
	z.c.Exp(z.c, x, z.n)
	return Witness{
		x: x,
		w: w,
		n: z.n,
		c: new(big.Int).Set(z.c),
	}
}

// Delete removes v from the accumulator and returns the witness
// proving non-membership.
//
// The results are undefined if v has not a member of the
// accumulator.
func (z *Accumulator) Delete(v []byte) Update {
	// A = A^(1/x mod 𝜑(N)) mod N
	x := hashToPrime(v)
	var inv big.Int
	z.c.Exp(z.c, inv.ModInverse(x, z.t), z.n)
	return Update{
		x: x,
		n: z.n,
		a: new(big.Int).Set(z.c),
	}
}

// Excludes reports whether the accumulator does not contain v.
func (z *Accumulator) Excludes(v []byte) bool {
	x := hashToPrime(v)

	// u' = u mod φ(N)
	var u big.Int
	u.Mod(z.u, z.t)

	// Find a,b such that au' + bx = 1.
	var a, b big.Int
	if !gcd(&a, &b, &u, x) {
		// gcd(x,u') != 1 so find a,b such that au' + bx = 1.
		//
		// Note that |x| in X where gcd(x,u') != 1 < k.
		gcd(&a, &b, z.u, x)
		// b' = b mod φ(N)
		b.Mod(&b, z.t)
	}

	var lhs, rhs big.Int
	lhs.Exp(z.c, &a, z.n) // c^a

	// d = g^-b mod N
	d := new(big.Int).Exp(g, b.Neg(&b), z.n)

	rhs.Exp(d, x, z.n) // d^x     mod N
	rhs.Mul(&rhs, g)   // d^x * g
	rhs.Mod(&rhs, z.n) //         mod N

	// c^a = d^-b * g mod N
	return lhs.Cmp(&rhs) == 0
}

// gcd returns the greatest common denominator of x and y and
// reports whether the GCD is one.
//
// It sets a and b such that a*x + b*y = 1.
func gcd(a, b, x, y *big.Int) bool {
	var v big.Int
	return v.GCD(a, b, x, y).Cmp(one) == 0
}

// Update applies the change to the witness and returns the
// updated witness.
func (z *Accumulator) Update(c Change, w Witness) Witness {
	if o, ok := c.(Witness); ok {
		return Witness{
			x: w.x,
			// w' = w^x mod N
			w: new(big.Int).Exp(w.w, o.x, z.n),
			n: z.n,
			c: w.c,
		}
	}
	o := c.(Update)

	var d, a, b big.Int
	d.GCD(&a, &b, w.x, o.x)

	var lhs, rhs big.Int
	rhs.Exp(o.a, &a, z.n) // rhs = A^a mod N
	lhs.Exp(w.w, &b, z.n) // lhs = w^b mod N

	return Witness{
		x: w.x,
		// w' = lhs*rhs mod N
		w: mulmod(&lhs, &rhs, z.n),
		n: z.n,
		c: w.c,
	}
}

func mulmod(x, y, n *big.Int) *big.Int {
	z := new(big.Int).Mul(x, y)
	return z.Mod(z, n)
}

// UpdateAll performs an in-place update on the witnesses.
func (z *Accumulator) UpdateAll(wits []Witness) {
	if len(wits) == 0 {
		return
	}
	for i, w := range wits[:len(wits)-1] {
		for j := i + 1; j < len(wits); j++ {
			w = z.Update(wits[j], w)
		}
		wits[i] = w
	}
}

// Verify reports whether the witness is valid.
func (z *Accumulator) Verify(w Witness) bool {
	var v big.Int
	return v.Exp(w.w, w.x, z.n).Cmp(z.c) == 0
}

func hashToPrime(v []byte) *big.Int {
	nonce := make([]byte, 4+len(v))
	copy(nonce[4:], v)

	var p big.Int
	for i := 0; i < math.MaxUint32; i++ {
		binary.LittleEndian.PutUint32(nonce, uint32(i))
		d := hash(nonce)
		p.SetBytes(d[:])
		if p.ProbablyPrime(20) {
			return &p
		}
	}
	panic("unreachable")
}

const hashSize = 16

// hash returns the first 16 bytes of SHA-256(v).
func hash(v []byte) [hashSize]byte {
	d := sha256.Sum256(v)
	t := d[:hashSize]
	// All primes are odd, but two is the oddest of them all.
	t[len(t)-1] |= 1
	return *(*[hashSize]byte)(t)
}
