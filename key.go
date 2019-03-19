package scramblekeys

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"strings"
	"time"

	ed25519 "golang.org/x/crypto/ed25519"
	sha3 "golang.org/x/crypto/sha3"
)

// Development NOTES
// TODO:
// * Build in subkey generation that are maintained in a merkle tree stored in
// the root key.
// * Add the ability to create certificates from this key, and generate
// sub-certificates.
// * Standardized message signign for standard operations on the various keys,
// sub-keys and certificates.

type KeyType int

// By defining specific Session key (think certificate), we can have keys
// issued for a session that even if hijacked have very limited permissions
const (
	RootKey KeyType = iota
	RecoveryKey
	SessionKey
)

type Ring struct {
	RootKey *Key            `json:"root_key,omitempty"`
	Keys    map[string]*Key `json:"keys"` // map[Key.Address]*Key
	// TODO: Make the tree here, hold all relation data here,
	// and even hold expiry data, which is created by signing
	// it with a parent key
	//Expires    time.Time          `json:"expires,omitempty"`
}

type Key struct {
	Address    string             `json:"address"`
	PublicKey  ed25519.PublicKey  `json:"public_key"`
	PrivateKey ed25519.PrivateKey `json:"private_key"`
	Expires    time.Time          `json:"expires,omitempty"`
}

func New(seed []byte) Key {
	r := bytes.NewReader(seed)
	publicKey, privateKey, _ := ed25519.GenerateKey(r)
	return Key{
		Address:    (GenerateAddress(publicKey)),
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}
}

func NewWithExpires(seed []byte, expiresAt time.Time) Key {
	r := bytes.NewReader(seed)
	publicKey, privateKey, _ := ed25519.GenerateKey(r)
	return Key{
		Address:    (GenerateAddress(publicKey)),
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Expires:    expiresAt,
	}
}

func GenerateKey() Key {
	return New(nil)
}

func GenerateDeterministicKey(seed []byte) Key {
	return New(seed)
}

func GenerateSessionKey(expiresAt time.Time) Key {
	return NewWithExpires(nil, expiresAt)
}

func (self Key) DerivativeKey() Key {
	return New(self.PrivateKey)
}

func (self Key) String() string {
	return string(self.JSON())
}

func (self Key) OnionAddress() string {
	return (self.Address + ".onion")
}

func (self Key) PGP() string {
	// TODO: Output a determinically generated PGP key based on any given key
	return ""
}

func (self Key) RSA() string {
	// TODO: Output a determinically generated SSH compatible RSA key based on any given key
	return ""
}

func (self Key) BTC() string {
	// TODO: Output a determinically generated BTC key based on any given key
	return ""
}

func (self Key) JSON() []byte {
	output, err := json.MarshalIndent(self, "", "  ")
	if err != nil {
		return []byte{}
	}
	return output
}

func GenerateAddress(publicKey ed25519.PublicKey) string {
	// checksum = H(".onion checksum" || pubkey || version)
	var byteBuffer bytes.Buffer
	byteBuffer.Write([]byte(".onion checksum"))
	byteBuffer.Write([]byte(publicKey))
	byteBuffer.Write([]byte{0x03})
	checksum := sha3.Sum256(byteBuffer.Bytes())
	byteBuffer.Reset()
	// onion_address = base32(pubkey || checksum || version)
	byteBuffer.Write([]byte(publicKey))
	byteBuffer.Write([]byte(checksum[:2]))
	byteBuffer.Write([]byte{0x03})
	return strings.ToLower((base32.StdEncoding.EncodeToString(byteBuffer.Bytes())))
}
