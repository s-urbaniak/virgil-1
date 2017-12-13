package pythia

import (
	"crypto/sha256"
	"math/big"

	"github.com/cloudflare/bn256"
	"golang.org/x/crypto/hkdf"
)

/*
def genKw(w,msk,z):
    """
    Generates key Kw using key-selector @w, master secret key @msk, and
    table value @z.
    @returns Kw as a BigInt.
    """
    # Hash inputs into a string of bytes
    b = hmac(msk, z + w, tag="TAG_PYTHIA_KW")

    # Convert the string into a long value (no larger than the order of Gt),
    # then return a BigInt value.
    return BigInt(longFromString(b) % long(orderGt()))
*/

func genKw(w, msk, z []byte) *big.Int {
	h := hkdf.New(sha256.New, msk, append(w, z...), []byte("TAG_PYTHIA_KW"))

	key := make([]byte, 32)
	h.Read(key)

	macInt := new(big.Int).SetBytes(key)
	res := macInt.Mod(macInt, bn256.Order)
	return res
}

func GetDelta(w1, msk1, z1 []byte, w2, msk2, z2 []byte) (*big.Int, *bn256.GT) {
	k := genKw(w1, msk1, z1)
	kPrime := genKw(w2, msk2, z2)

	inv := fermatInverse(k, bn256.Order)

	delta := new(big.Int).Mod(new(big.Int).Mul(kPrime, inv), bn256.Order)

	pPrime := new(bn256.GT).ScalarBaseMult(kPrime)
	return delta, pPrime
}

func Update(z *bn256.GT, delta *big.Int) *bn256.GT {
	return new(bn256.GT).ScalarMult(z, delta)
}
