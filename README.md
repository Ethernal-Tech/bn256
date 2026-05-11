
bn256
=====

This repository contains a Go implementation of the BN256 (also called alt_bn128)
pairing-friendly elliptic curve and related finite-field arithmetic. It provides
curve operations, field arithmetic, and test vectors used by cryptographic
protocols that rely on pairings.

Cloudflare directory
-------------------

The `cloudflare/` subdirectory is a copy of the implementation shipped in
the go-ethereum project for compatibility and reference. See
https://github.com/ethereum/go-ethereum/tree/master/crypto/bn256/cloudflare
for the original source.

Quick start
-----------

- Run tests: `go test ./...`
- Build or import: use this package in your Go modules as needed.

