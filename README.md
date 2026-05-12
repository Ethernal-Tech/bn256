
bn256
=====

This repository contains a Go implementation of the `bn256` package — a
historical package name used by Cloudflare and go-ethereum. The implementation
actually targets the BN254 curve (also called alt_bn128), despite the
`bn256` package name. It provides curve operations, field arithmetic, and
test vectors used by cryptographic protocols that rely on pairings.

Cloudflare directory
-------------------

The `cloudflare/` subdirectory is a copy of the implementation shipped in
the go-ethereum project for compatibility and reference. See
https://github.com/ethereum/go-ethereum/tree/master/crypto/bn256/cloudflare
for the original source.

Note on naming
---------------

The package is commonly called `bn256` in Go ecosystems for historical
reasons, but the curve parameters and constants correspond to BN254
(a.k.a. `alt_bn128`). If you prefer, refer to the curve as BN254/alt_bn128
in documentation and external references to avoid confusion.

Quick start
-----------

- Run tests: `go test ./...`
- Build or import: use this package in your Go modules as needed.

