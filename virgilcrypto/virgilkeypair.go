package virgilcrypto

/*
Copyright (C) 2015-2016 Virgil Security Inc.

Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

  (1) Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  (2) Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in
  the documentation and/or other materials provided with the
  distribution.

  (3) Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"

	"crypto/subtle"

	"github.com/agl/ed25519"
)

type Keypair interface {
	HasPublic() bool
	HasPrivate() bool
	PublicKey() PublicKey
	PrivateKey() PrivateKey
}

var NewKeypair func() (Keypair, error)

const EC_PRIVATE_KEY = "PRIVATE KEY"
const ENCRYPTED_PRIVATE_KEY = "ENCRYPTED PRIVATE KEY"
const PUBLIC_KEY = "PUBLIC KEY"

var PEM_START = []byte("-----BEGIN ")

type ed25519Keypair struct {
	publicKey  *ed25519PublicKey
	privateKey *ed25519PrivateKey
}

func generateEd25519Keypair() (Keypair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		return nil, cryptoError(err, "")
	}

	pub := &ed25519PublicKey{key: publicKey[:]}
	priv := &ed25519PrivateKey{key: privateKey[:]}
	kp := &ed25519Keypair{}
	kp.publicKey = pub
	kp.privateKey = priv

	snapshot, err := pub.Encode()
	if err != nil {
		return nil, cryptoError(err, "")
	}
	fp := DefaultCrypto.CalculateFingerprint(snapshot)

	pub.receiverID = fp
	priv.receiverID = make([]byte, len(fp))
	copy(priv.receiverID, fp)
	return kp, nil
}
func (e *ed25519Keypair) HasPublic() bool {
	return e.publicKey != nil && !e.publicKey.Empty()
}
func (e *ed25519Keypair) HasPrivate() bool {
	return e.privateKey != nil && !e.privateKey.Empty()
}
func (e *ed25519Keypair) PublicKey() PublicKey {
	return e.publicKey
}
func (e *ed25519Keypair) PrivateKey() PrivateKey {
	return e.privateKey
}

func unwrapKey(key []byte) ([]byte, string, error) {
	if len(key) < len(PEM_START) {
		return nil, "", CryptoError("Key is too small")
	}
	start := key[:len(PEM_START)]
	if subtle.ConstantTimeCompare(start, PEM_START) == 0 {

		//try unbase64
		decoded, err := base64.StdEncoding.DecodeString(string(key))
		if err == nil {
			return decoded, "", nil
		}

		return key, "", nil //already DER
	}

	block, _ := pem.Decode(key)
	if block != nil {
		return block.Bytes, block.Type, nil
	}
	return nil, "", CryptoError("could not decode PEM structure")
}

func init() {
	NewKeypair = generateEd25519Keypair
}