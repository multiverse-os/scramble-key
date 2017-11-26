package main

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"lib/atomicio"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

type KeyPair struct {
	Address    string             `json:address`
	PublicKey  ed25519.PublicKey  `json:public_key`
	PrivateKey ed25519.PrivateKey `json:private_key`
}

func main() {
	keyPair := GenerateKey()
	keyFilePath := ".scramble-suit.key"

	encodedKeyFile, _ := keyPair.encodeJSON("  ")
	fmt.Println("Saving JSON Encoded Key File:")
	fmt.Println(encodedKeyFile)

	WriteJSONKeyFile(keyFilePath, keyPair)
}

func WriteJSONKeyFile(keyFilePath string, keyPair KeyPair) {
	if _, err := os.Stat(keyFilePath); os.IsNotExist(err) {
		keyFile, _ := safefile.Create(keyFilePath, 0644)
		defer keyFile.Close()

		encodedKeyFile, _ := keyPair.encodeJSON("  ")

		_, _ = io.WriteString(keyFile, encodedKeyFile)
		err = keyFile.Commit()
		if err != nil {
			fmt.Println("Error: ", err)
		} else {
			fmt.Println("File successfully written.")
		}
	} else {
		fmt.Println("File exists.")
	}
}

func (keyPair KeyPair) encodeJSON(indent string) (string, error) {
	output, err := json.MarshalIndent(keyPair, "", indent)
	if err != nil {
		return "", err
	}
	return string(output), err
}

func GenerateKey() KeyPair {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	return KeyPair{
		Address:    (GenerateAddress(publicKey)),
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}
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
