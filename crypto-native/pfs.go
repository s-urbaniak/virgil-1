package cryptonative

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/minio/sha256-simd"
	"golang.org/x/crypto/hkdf"
)

type (
	PFSSession struct {
		SKa, SKb, AD, SessionID []byte
		Initiator               bool
	}

	PFS interface {
		StartPFSSession(ICb, LTCb, OTCb PublicKey, ICa, EKa PrivateKey, additionalData []byte) (sess *PFSSession, err error)
		ReceivePFCSession(ICa, EKa PublicKey, ICb, LTCb, OTCb PrivateKey, additionalData []byte) (sess *PFSSession, err error)
	}
)

var virgil = []byte("Virgil")

func (c *VirgilCrypto) StartPFSSession(ICb, LTCb, OTCb PublicKey, ICa, EKa PrivateKey, additionalData []byte) (sess *PFSSession, err error) {

	sk, err := EDHInit(ICa, EKa, ICb, LTCb, OTCb)
	if err != nil {
		return
	}

	ska, skb := sk[:64], sk[64:]

	toHash := make([]byte, 0, len(additionalData)+len(virgil))
	toHash = append(toHash, additionalData...)
	toHash = append(toHash, []byte(virgil)...)

	hash := sha256.Sum256(toHash)

	ad := hash[:]

	toHash = make([]byte, 0, len(sk)+len(ad)+len(virgil))

	toHash = append(sk, ad...)
	toHash = append(toHash, []byte(virgil)...)

	sessHash := sha256.Sum256(toHash)
	sessionID := sessHash[:]

	return &PFSSession{
		Initiator: true,
		SKa:       ska,
		SKb:       skb,
		AD:        ad,
		SessionID: sessionID,
	}, nil

}

func (c *VirgilCrypto) ReceivePFCSession(ICa, EKa PublicKey, ICb, LTCb, OTCb PrivateKey, additionalData []byte) (sess *PFSSession, err error) {

	sk, err := EDHRespond(ICa, EKa, ICb, LTCb, OTCb)
	if err != nil {
		return
	}
	ska, skb := sk[:64], sk[64:]

	toHash := make([]byte, 0, len(additionalData)+len(virgil))
	toHash = append(toHash, additionalData...)
	toHash = append(toHash, []byte(virgil)...)

	hash := sha256.Sum256(toHash)

	ad := hash[:]

	toHash = make([]byte, 0, len(sk)+len(ad)+len(virgil))

	toHash = append(sk, ad...)
	toHash = append(toHash, []byte(virgil)...)

	sessHash := sha256.Sum256(toHash)
	sessionID := sessHash[:]

	return &PFSSession{
		Initiator: false,
		SKa:       ska,
		SKb:       skb,
		AD:        ad,
		SessionID: sessionID,
	}, nil

}

func (s *PFSSession) Encrypt(plaintext []byte) (salt, ciphertext []byte) {
	salt = make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	keyAndNonce := make([]byte, 44)

	sk := s.SKa

	if !s.Initiator {
		sk = s.SKb
	}

	kdf := hkdf.New(sha256.New, sk, salt, virgil)

	_, err = kdf.Read(keyAndNonce)
	if err != nil {
		panic(err)
	}

	ciph, _ := aes.NewCipher(keyAndNonce[:32])
	aesGCM, _ := cipher.NewGCM(ciph)
	ciphertext = aesGCM.Seal(nil, keyAndNonce[32:], plaintext, s.AD)
	return
}

func (s *PFSSession) Decrypt(salt, ciphertext []byte) ([]byte, error) {

	keyAndNonce := make([]byte, 44)

	sk := s.SKb

	if !s.Initiator {
		sk = s.SKa
	}

	kdf := hkdf.New(sha256.New, sk, salt, virgil)

	_, err := kdf.Read(keyAndNonce)
	if err != nil {
		panic(err)
	}

	ciph, _ := aes.NewCipher(keyAndNonce[:32])
	aesGCM, _ := cipher.NewGCM(ciph)
	return aesGCM.Open(nil, keyAndNonce[32:], ciphertext, s.AD)
}