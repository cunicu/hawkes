# hawkes: Hardware-secured Key Establishment

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/cunicu/hawkes/test.yaml?style=flat-square)](https://github.com/cunicu/hawkes/actions)
[![goreportcard](https://goreportcard.com/badge/github.com/cunicu/hawkes?style=flat-square)](https://goreportcard.com/report/github.com/cunicu/hawkes)
[![Codecov branch](https://img.shields.io/codecov/c/github/cunicu/hawkes/main?style=flat-square&token=6XoWouQg6K)](https://app.codecov.io/gh/cunicu/hawkes/tree/main)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](https://github.com/cunicu/hawkes/blob/main/LICENSES/Apache-2.0.txt)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/cunicu/hawkes?style=flat-square)
[![Go Reference](https://pkg.go.dev/badge/github.com/cunicu/hawkes.svg)](https://pkg.go.dev/github.com/cunicu/hawkes)

`hawkes` is a Go package providing a interface to establish shared secrets between two parties.
It includes implementations of this interface for:

- OATH-HOTP/TOPT ([RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226), [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238))
    - Hardware: [Yubikey (YKOATH)](https://developers.yubico.com/OATH/YKOATH_Protocol.html)
    - Software
- PIV smart-cards[^1]
- GPG smart-cards[^1]
- Post Quantum [Rosenpass handshake](https://rosenpass.eu)[^1]

[^1]: Planned

hawkes' main use case is the establishment of pre-shared keys for WireGuard using hardware-backed or post-quantum resilient implementations.

## Install

When build with `CGO_ENABLED`, hawkes requires the following external dependencies.

```bash
apt-get install \
    libpcsclite-dev
```

When used with age plugins, the respective plugins must be present in `$PATH`.

## Authors

- Steffen Vogel ([@stv0g](https://github.com/stv0g))

## License

hawkes is licensed under the [Apache 2.0](./LICENSE) license.

- SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
- SPDX-License-Identifier: Apache-2.0
