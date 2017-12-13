package keyknox

import (
	"math/big"

	"github.com/cloudflare/bn256"
	"github.com/pkg/errors"
	"gopkg.in/virgil.v6/keyknox/pythia"
)

type PRF struct {
}

func (prf PRF) Eval(keySelector, tweak, blindedMsg, masterKey, clientKey []byte) (result []byte, keyBound []byte, tilde []byte, err error) {
	var x bn256.G1
	_, err = x.Unmarshal(blindedMsg)
	if err != nil {
		return result, keyBound, tilde, errors.Wrapf(err, "PRF.Eval: blindedMsg should be bn256.G1 marshaled data")
	}

	y, kw, tTilde, err := pythia.Eval(keySelector, tweak, &x, masterKey, clientKey)
	if err != nil {
		return result, keyBound, tilde, errors.Wrapf(err, "PRF.Eval(%s,%s,%x,%x,%x): Pythia.Eval return error", keySelector, tweak, blindedMsg, masterKey, clientKey)
	}
	result = y.Marshal()
	keyBound = kw.Bytes()
	tilde = tTilde.Marshal()
	return result, keyBound, tilde, nil
}

func (prf PRF) Prove(blindedMsg, tilde, keyBound, result []byte) (proof Proof, err error) {
	var (
		x      bn256.G1
		tTilde bn256.G2
		kw     big.Int
		y      bn256.GT
	)
	_, err = x.Unmarshal(blindedMsg)
	if err != nil {
		return proof, errors.Wrapf(err, "PRF.Prove: blindedMsg should be bn256.G1 marshaled data")
	}
	_, err = tTilde.Unmarshal(tilde)
	if err != nil {
		return proof, errors.Wrapf(err, "PRF.Prove: tilde should be bn256.G2 marshaled data")
	}
	_, err = y.Unmarshal(result)
	if err != nil {
		return proof, errors.Wrapf(err, "PRF.Prove: result should be bn256.GT marshaled data")
	}
	kw.SetBytes(keyBound)
	p, c, u := pythia.Prove(&x, &tTilde, &kw, &y)

	return Proof{
		P: p.Marshal(),
		C: c.Bytes(),
		U: u.Bytes(),
	}, nil
}

// func (prf PRF)Verify(x *bn256.G1, t []byte, y *bn256.GT, p *bn256.G1, c, u *big.Int) error {
func (prf PRF) Verify(blindedMsg []byte, tweak string, result []byte, proof Proof) error {
	var (
		x bn256.G1
		y bn256.GT
		p bn256.G1
	)
	_, err := x.Unmarshal(blindedMsg)
	if err != nil {
		return errors.Wrapf(err, "PRF.Verify: blindedMsg should be bn256.G1 marshaled data")
	}
	_, err = y.Unmarshal(result)
	if err != nil {
		return errors.Wrapf(err, "PRF.Verify: result should be bn256.GT marshaled data")
	}
	_, err = p.Unmarshal(proof.P)
	if err != nil {
		return errors.Wrapf(err, "PRF.Verify: p should be bn256.G1 marshaled data")
	}
	err = pythia.Verify(&x, []byte(tweak), &y, &p, new(big.Int).SetBytes(proof.C), new(big.Int).SetBytes(proof.U))
	return errors.Wrap(err, "PRF.Verify")
}

func (prf PRF) Rotate(keySelector, masterKey, clientKey, newKeySelector, newMasterKey, newClient []byte) (delta []byte, newResult []byte, err error) {
	d, r := pythia.GetDelta(keySelector, masterKey, clientKey, newKeySelector, newMasterKey, newClient)
	return d.Bytes(), r.Marshal(), nil
}

func (prf PRF) Update(oldValue []byte, delta []byte) ([]byte, error) {
	var (
		z bn256.GT
	)
	_, err := z.Unmarshal(oldValue)
	if err != nil {
		return nil, errors.Wrapf(err, "PRF.Update: oldValue should be bn256.GT marshaled data")
	}
	newZ := pythia.Update(&z, new(big.Int).SetBytes(delta))
	return newZ.Marshal(), nil
}

func (prf PRF) Blind(password string) (rInv []byte, x []byte, err error) {

	rX, X, err := pythia.Blind([]byte(password))
	if err != nil {
		return nil, nil, errors.Wrapf(err, "PRF.Blind")
	}

	return rX.Bytes(), X.Marshal(), nil
}

func (prf PRF) Deblind(rInv []byte, result []byte) ([]byte, error) {
	var y bn256.GT
	_, err := y.Unmarshal(result)
	if err != nil {
		return nil, errors.Wrapf(err, "PRF.Deblind: result should be bn256.GT marshaled data")
	}

	r := pythia.Deblind(new(big.Int).SetBytes(rInv), &y)
	return r.Marshal(), nil
}
