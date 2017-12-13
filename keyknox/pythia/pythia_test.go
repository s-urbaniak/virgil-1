package pythia

import (
	"testing"

	"github.com/cloudflare/bn256"
	"github.com/stretchr/testify/assert"
)

var (
	w   = []byte("Some super-secret ensemble key selector")
	t   = []byte("Totally random and unpredictable tweak")
	m   = []byte("This is a secret message")
	msk = []byte("lkjasdf;lkjas;dlkfa;slkdf;laskdjf")
	s   = []byte("Super secret table value")
)

func TestEvalStable(tz *testing.T) {

	var z *bn256.GT

	for i := 0; i < 100; i++ {
		r, x, _ := Blind(m)
		y, _, _, _ := Eval(w, t, x, msk, s)
		zz := Deblind(r, y)

		if z == nil {
			z = zz
		} else {
			assert.Equal(tz, z.Marshal(), zz.Marshal())
		}
	}

}

func TestFullProtocol(tz *testing.T) {
	/*
			 r, x = blind(m)
		   	 y,kw,tTilde = eval(w,t,x,msk,s)
		     pi = prove(x, tTilde, kw, y)
		     z = deblind(r, y)

		     # Check the proof
		     self.assertTrue( verify(x, t, y, pi) )
	*/

	var z *bn256.GT
	var p *bn256.G1
	for i := 0; i < 100; i++ {
		r, x, err := Blind(m)
		assert.NoError(tz, err)
		y, kw, tTilde, err := Eval(w, t, x, msk, s)
		assert.NoError(tz, err)

		p1, c, u := Prove(x, tTilde, kw, y)

		if p == nil {
			p = p1
		} else {
			assert.Equal(tz, p.Marshal(), p1.Marshal())
		}

		if z == nil {
			z = Deblind(r, y)
		} else {
			assert.Equal(tz, z.Marshal(), Deblind(r, y).Marshal())
		}

		assert.NoError(tz, Verify(x, t, y, p, c, u))
	}

}

func TestUpdate(tz *testing.T) {

	wPrime := []byte("Definitely not the original value w")
	sPrime := []byte("Totally new state value")

	z := simpleProto(tz, w, t, msk, s, m)

	delta, _ := GetDelta(w, msk, s, wPrime, msk, sPrime) //delta is the update token
	zPrime1 := Update(z, delta)

	zPrime2 := simpleProto(tz, wPrime, t, msk, sPrime, m)
	assert.Equal(tz, zPrime1.Marshal(), zPrime2.Marshal())

}

func simpleProto(tz *testing.T, w, t []byte, msk, s, m []byte) *bn256.GT {
	r, x, err := Blind(m)
	assert.NoError(tz, err)

	y, _, _, err := Eval(w, t, x, msk, s)
	assert.NoError(tz, err)

	z := Deblind(r, y)
	return z
}
