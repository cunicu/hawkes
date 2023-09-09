// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"cunicu.li/hawkes/providers/ecdh/se"
)

var (
	label = flag.String("label", "my-label", "User visible label of the generated key pair")
	tag   = flag.String("tag", "my-tag", "An internal tag")
)

func main() {
	if len(os.Args) < 2 {
		panic("invalid usage")
	}

	switch os.Args[1] {
	case "genkey":
		pk, err := se.GenerateKeyPair(*label, *tag)
		if err != nil {
			panic(err)
		}

		fmt.Println(base64.StdEncoding.EncodeToString(pk))

	case "shared-secret":
	}
}
