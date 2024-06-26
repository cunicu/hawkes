# SPDX-FileCopyrightText: 2023-2024 Steffen Vogel <post@steffenvogel.de>
# SPDX-License-Identifier: Apache-2.0

CODESIGN_IDENTITY ?= "Apple Development: post@steffenvogel.de"

all: hawkes

hawkes: ./assets/entitlements.xml
	go build -o $@ ./cmd
	codesign -f -s ${CODESIGN_IDENTITY} --entitlements ./assets/entitlements.xml $@

provider-test:
	go test -c -o $@ ./provider
	codesign -f -s ${CODESIGN_IDENTITY} --entitlements ./assets/entitlements.xml $@

.PHONY: all hawkes provider-test
