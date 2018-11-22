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
//   * Add the ability to generate a key form another key deterministically
//   * Be able to verify child keys against any parent key
//   * Use merkle tree to have piece-meal verification against the merkle root
//   * Patricia tree based key lookup

type KeyType int

// By defining specific Session key (think certificate), we can have keys
// issued for a session that even if hijacked have very limited permissions
const (
	Root KeyType = iota
	Recovery
	Session
)

type Ring struct {
	RootKey *Key            `json:"root_key,omitempty"`
	Keys    map[string]*Key `json:"keys"` // map[Key.Address]*Key
}

type Key struct {
	ParentKey  Key                `json:"parent_key,omitempty"`
	ChildKeys  map[string]Key     `json:"child_keys,omitempty"`
	Address    string             `json:"address"`
	PublicKey  ed25519.PublicKey  `json:"public_key"`
	PrivateKey ed25519.PrivateKey `json:"private_key"`
	Expires    time.Time          `json:"expires,omitempty"`
}

func New(seed []byte, expiresAt time.Time) Key {
	publicKey, privateKey, _ := ed25519.GenerateKey(seed)
	return Key{
		Address:    (GenerateAddress(publicKey)),
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		Expires:    expiresAt,
	}
}

func GenerateKey() Key {
	return New(nil, nil)
}

func DeterministicKey(seed []byte) Key {
	return New(seed, nil)
}

func SessionKey(expiresAt time.Time) Key {
	return New(nil, expiresAt)
}

func (self Key) DerivativeKey() Key {
	return New(string(self.PrivateKey), nil)
}

func (self Key) String() string {
	return string(self.JSON())
}

func (self Key) OnionAddress() string {
	return (self.Address + ".onion")
}

func (self Key) PGP() string {
	// TODO: Output a determinically generated PGP key based on any given key
}

func (self Key) RSA() string {
	// TODO: Output a determinically generated SSH compatible RSA key based on any given key
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
