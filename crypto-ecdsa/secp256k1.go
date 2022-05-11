package ecdsa

import (
	"github.com/umbracle/ethgo/crypto-ecdsa/secp256k1"
)

func S256() *secp256k1.KoblitzCurve {
	return secp256k1.S256()
}
