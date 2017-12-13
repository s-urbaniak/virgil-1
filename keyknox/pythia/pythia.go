package pythia

import (
	"math/big"

	"github.com/cloudflare/bn256"
	"github.com/pkg/errors"
)

/*
Pythia server-side computation of intermediate PRF output.
    @w: ensemble key selector (e.g. webserver ID)
    @t: tweak (e.g. user ID)
    @x: blinded message (element of G1)
    @msk: Pythia server's master secret key
    @s: state value from Pythia server's key table
    @returns: (y, kw, tTile)
     where: y: intermediate result
            kw: secret key bound to w (needed for proof)
            tTilde: hashed tweak (needed for proof)
*/

func Eval(w, t []byte, x *bn256.G1, msk, s []byte) (y *bn256.GT, kw *big.Int, tTilde *bn256.G2, err error) {

	kw = genKw(w, msk, s)

	tTilde, err = hashG2(t)
	if err != nil {
		return
	}

	xkw := new(bn256.G1).ScalarMult(x, kw)
	y = bn256.Pair(xkw, tTilde)

	return
}

/*
Generate a zero-knowledge proof that DL(Q*kw) == DL(e(x,tTilde)^kw) where
    <Q> = G1.
    @x: Blinded message from client request.
    @tTilde: HG2(t), element of G2
    @kw: secret key derived from w
    @y: intermediate result from eval function. element of Gt
*/
func Prove(x *bn256.G1, tTilde *bn256.G2, kw *big.Int, y *bn256.GT) (p *bn256.G1, c, u *big.Int) {

	beta := bn256.Pair(x, tTilde)
	p = new(bn256.G1).ScalarBaseMult(kw)
	v := randomZ(bn256.Order)
	t1 := new(bn256.G1).ScalarBaseMult(v)
	t2 := new(bn256.GT).ScalarMult(beta, v)

	c = hashZ(serializedG1Gen, p.Marshal(), beta.Marshal(), y.Marshal(), t1.Marshal(), t2.Marshal())

	ckw := new(big.Int).Mul(c, kw)
	u = new(big.Int).Sub(v, ckw)
	u.Mod(u, bn256.Order)
	return
}

/*
Verifies a zero-knowledge proof where p \in G1.
*/
func Verify(x *bn256.G1, t []byte, y *bn256.GT, p *bn256.G1, c, u *big.Int) error {

	hg2, err := hashG2(t)
	if err != nil {
		return err
	}
	beta := bn256.Pair(x, hg2)
	t1 := new(bn256.G1).Add(new(bn256.G1).ScalarBaseMult(u), new(bn256.G1).ScalarMult(p, c))
	tmp1 := new(bn256.GT).ScalarMult(y, c)
	tmp2 := new(bn256.GT).ScalarMult(beta, u)
	t2 := new(bn256.GT).Add(tmp1, tmp2)

	cPrime := hashZ(serializedG1Gen, p.Marshal(), beta.Marshal(), y.Marshal(), t1.Marshal(), t2.Marshal())
	if cPrime.Cmp(c) != 0 {
		return errors.New("zero-knowledge proof failed verification.")
	}
	return nil
}

func Blind(password []byte) (rInv *big.Int, x *bn256.G1, err error) {

	r := randomZ(nil)
	rInv = fermatInverse(r, bn256.Order)

	x, err = hashG1(password)
	if err != nil {
		return
	}

	x.ScalarMult(x, r)

	return
}

func Deblind(rInv *big.Int, y *bn256.GT) *bn256.GT {
	return new(bn256.GT).ScalarMult(y, rInv)
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method.
// This has better constant-time properties than Euclid's method (implemented
// in math/big.Int.ModInverse) although math/big itself isn't strictly
// constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}
