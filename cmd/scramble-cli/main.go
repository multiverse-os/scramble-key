package main

import (
	"fmt"

	scramble "github.com/multiverse-os/scramblekeys"
)

// TODO: Scramble keys should exist within a ephemeral key tree system
// this will allow session creation and destruction, with time based
// expiration as one method to revoke session keys

// TODO: Build out a CLI that allows for generation, listing, tree management,
// deletion, revokation, session generation, verification, etc
func main() {
	keyPair := scramble.GenerateKey()
	keyFilePath := ".scramble-suit.key"

	encodedKeyFile, _ := keyPair.encodeJSON("  ")
	fmt.Println("Saving JSON Encoded Key File:")
	fmt.Println(encodedKeyFile)

	WriteJSONKeyFile(keyFilePath, keyPair)
}
