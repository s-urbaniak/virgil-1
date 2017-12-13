package pythia

import (
	"crypto/rand"
	"math/big"

	"github.com/cloudflare/bn256"
	"golang.org/x/crypto/sha3"
)

var serializedG1Gen = generatorG1().Marshal()

func hashG2(x []byte) (*bn256.G2, error) {
	xof := sha3.NewShake256()
	xof.Write(x)
	_, g2, err := bn256.RandomG2(xof)
	return g2, err
}

func hashG1(x []byte) (*bn256.G1, error) {
	xof := sha3.NewShake256()
	xof.Write(x)
	_, g2, err := bn256.RandomG1(xof)
	return g2, err
}

func randomZ(max *big.Int) *big.Int {

	buf := make([]byte, 32) //256 bits
	rand.Read(buf)
	tmp := new(big.Int).SetBytes(buf)

	if max != nil {
		return tmp.Mod(tmp, max)
	} else {
		return tmp
	}

}

func hashZ(args ...[]byte) *big.Int {

	hash := sha3.NewShake256()

	for _, arg := range args {
		hash.Write(arg)
	}

	buf := make([]byte, 32)
	hash.Read(buf)
	return new(big.Int).SetBytes(buf)
}

func generatorG1() *bn256.G1 {
	one := big.NewInt(1)
	g1 := new(bn256.G1).ScalarBaseMult(one)
	return g1
}
