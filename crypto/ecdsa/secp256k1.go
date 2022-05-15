package ecdsa

import (
	secp256k12 "github.com/git-yongge/ethgo/crypto/ecdsa/secp256k1"
)

func S256() *secp256k12.KoblitzCurve {
	return secp256k12.S256()
}
