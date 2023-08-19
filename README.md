# go-skes: Shared Key Establishment

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/cunicu/go-skes/test.yaml?style=flat-square)](https://github.com/cunicu/go-skes/actions)
[![goreportcard](https://goreportcard.com/badge/github.com/cunicu/go-skes?style=flat-square)](https://goreportcard.com/report/github.com/cunicu/go-skes)
[![Codecov branch](https://img.shields.io/codecov/c/github/cunicu/go-skes/main?style=flat-square&token=6XoWouQg6K)](https://app.codecov.io/gh/cunicu/go-skes/tree/main)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](https://github.com/cunicu/go-skes/blob/main/LICENSES/Apache-2.0.txt)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/cunicu/go-skes?style=flat-square)
[![Go Reference](https://pkg.go.dev/badge/github.com/cunicu/go-skes.svg)](https://pkg.go.dev/github.com/cunicu/go-skes)

`go-skes` is a Go package providing a common interface to establish shared secrets between two parties.
It includes implementations of this interface for:

- Yubikey OATH (YKOATH)
- Software OATH
- PIV[^1]
- GPG[^1]
- Post Quantum [Rosenpass handshake](https://rosenpass.eu)

[^1]: Planned

## Install

```bash
apt-get install \
    libpcsclite-dev
```

## Authors

- Steffen Vogel ([@stv0g](https://github.com/stv0g))

## License

go-skes is licensed under the [Apache 2.0](./LICENSE) license.


- SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
- SPDX-License-Identifier: Apache-2.0