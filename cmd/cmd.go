// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"log/slog"
	"os"

	se "cunicu.li/hawkes/ecdh/applese"
	"cunicu.li/hawkes/ecdh/sw"
)

func main() {
	if len(os.Args) < 2 {
		slog.Error("Usage: hawkes (list|remove|genkey)")
		os.Exit(-1)
	}

	switch os.Args[1] {
	case "genkey":
		label := "label"
		if len(os.Args) >= 3 {
			label = os.Args[2]
		}

		sk, err := se.GenerateKey(label)
		if err != nil {
			slog.Error("Failed to generate key", slog.Any("error", err))
			os.Exit(-1)
		}

		fmt.Println(sk.Label())

	case "diffie-helman", "dh":
		if len(os.Args) < 4 {
			slog.Error("Usage: hawkes dh [label] [public-key]")
			os.Exit(-1)
		}

		labelBytes, err := base64.StdEncoding.DecodeString(os.Args[2])
		if err != nil {
			slog.Error("Failed to decode", slog.Any("error", err))
			os.Exit(-1)
		}

		label := se.KeyLabel(labelBytes)

		sk, err := se.PrivateKeyByLabel(label)
		if err != nil {
			slog.Error("Failed to get private key", slog.Any("error", err))
			os.Exit(-1)
		}

		pkBytes, err := base64.StdEncoding.DecodeString(os.Args[3])
		if err != nil {
			slog.Error("Failed to decode", slog.Any("error", err))
			os.Exit(-1)
		}

		pk, err := sw.P256.ParsePublicKey(pkBytes)
		if err != nil {
			slog.Error("Failed to load public key", slog.Any("error", err))
			os.Exit(-1)
		}

		ss, err := sk.DH(pk)
		if err != nil {
			slog.Error("Failed to calc shared secret", slog.Any("error", err))
			os.Exit(-1)
		}

		fmt.Println(base64.StdEncoding.EncodeToString(ss))

	case "remove", "rm":
		var err error
		var hash []byte

		if len(os.Args) < 3 {
			slog.Error("Usage: hawkes remove [label]")
			os.Exit(-1)
		}

		if hash, err = base64.StdEncoding.DecodeString(os.Args[2]); err != nil {
			slog.Error("Failed to decode key label", slog.Any("error", err))
			os.Exit(-1)
		}

		if ok, err := se.RemoveKey(se.KeyLabel(hash)); err != nil {
			slog.Error("Failed to remove key", slog.Any("error", err))
			os.Exit(-1)
		} else if !ok {
			slog.Warn("No matching key found")
		}

	case "list", "ls":
		var err error
		var hash []byte

		if len(os.Args) > 2 {
			if hash, err = base64.StdEncoding.DecodeString(os.Args[2]); err != nil {
				slog.Error("Failed to decode key label", slog.Any("error", err))
				os.Exit(-1)
			}
		}

		keys, err := se.Keys(hash)
		if err != nil {
			slog.Error("Failed to enumerate keys", slog.Any("error", err))
			os.Exit(-1)
		}

		for _, key := range keys {
			pkStr := base64.StdEncoding.EncodeToString(key.Public().Bytes())
			log.Println(key.Label(), pkStr)
		}
	}
}
