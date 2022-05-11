package ecdsa

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/git-yongge/ethgo/crypto-ecdsa/secp256k1"
	"math/big"
)

type PublicKey ecdsa.PublicKey

const (
	PubKeyBytesLenCompressed   = 33
	PubKeyBytesLenUncompressed = 65
	PubKeyBytesLenHybrid       = 65

	pubkeyCompressed   byte = 0x2 // y_bit + x coord
	pubkeyUncompressed byte = 0x4 // x coord + y coord
	pubkeyHybrid       byte = 0x6 // y_bit + x coord + y coord
)

// ToECDSA returns the public key as a *ecdsa.PublicKey.
func (p *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return (*ecdsa.PublicKey)(p)
}

// SerializeUncompressed serializes a public key in a 65-byte uncompressed format.
func (p *PublicKey) SerializeUncompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenUncompressed)
	b = append(b, pubkeyUncompressed)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

// SerializeCompressed serializes a public key in a 33-byte compressed format.
func (p *PublicKey) SerializeCompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubkeyCompressed
	if isOdd(p.Y) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(32, b, p.X.Bytes())
}

// SerializeHybrid serializes a public key in a 65-byte hybrid format.
func (p *PublicKey) SerializeHybrid() []byte {
	b := make([]byte, 0, PubKeyBytesLenHybrid)
	format := pubkeyHybrid
	if isOdd(p.Y) {
		format |= 0x1
	}
	b = append(b, format)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

// ToCompressHex return 66-bit hexadecimal strings
func (p *PublicKey) ToCompressHex() string {
	return hex.EncodeToString(p.SerializeCompressed())
}

// ToCompressHex return 130-bit hexadecimal strings
func (p *PublicKey) Hex() string {
	return hex.EncodeToString(p.SerializeUncompressed())
}

// IsEqual 根据xy判断公钥是否相等
func (p *PublicKey) IsEqual(otherPubKey *PublicKey) bool {
	return p.X.Cmp(otherPubKey.X) == 0 && p.Y.Cmp(otherPubKey.Y) == 0
}

// ParsePubKey 公钥反序列化
func ParsePubKey(pubKeyStr []byte, curve *secp256k1.KoblitzCurve) (key *PublicKey, err error) {
	pubkey := PublicKey{}
	pubkey.Curve = curve

	if len(pubKeyStr) == 0 {
		return nil, errors.New("pubkey string is empty")
	}

	format := pubKeyStr[0]
	ybit := (format & 0x1) == 0x1
	format &= ^byte(0x1)

	switch len(pubKeyStr) {
	case PubKeyBytesLenUncompressed:
		if format != pubkeyUncompressed && format != pubkeyHybrid {
			return nil, fmt.Errorf("invalid magic in pubkey str: "+"%d", pubKeyStr[0])
		}

		pubkey.X = new(big.Int).SetBytes(pubKeyStr[1:33])
		pubkey.Y = new(big.Int).SetBytes(pubKeyStr[33:])
		// hybrid keys have extra information, make use of it.
		if format == pubkeyHybrid && ybit != isOdd(pubkey.Y) {
			return nil, fmt.Errorf("ybit doesn't match oddness")
		}

		if pubkey.X.Cmp(pubkey.Curve.Params().P) >= 0 {
			return nil, fmt.Errorf("pubkey X parameter is >= to P")
		}
		if pubkey.Y.Cmp(pubkey.Curve.Params().P) >= 0 {
			return nil, fmt.Errorf("pubkey Y parameter is >= to P")
		}
		if !pubkey.Curve.IsOnCurve(pubkey.X, pubkey.Y) {
			return nil, fmt.Errorf("pubkey isn't on secp256k1 curve")
		}

	case PubKeyBytesLenCompressed:
		// format is 0x2 | solution, <X coordinate>
		// solution determines which solution of the curve we use.
		/// y^2 = x^3 + Curve.B
		if format != pubkeyCompressed {
			return nil, fmt.Errorf("invalid magic in compressed "+
				"pubkey string: %d", pubKeyStr[0])
		}
		pubkey.X = new(big.Int).SetBytes(pubKeyStr[1:33])
		pubkey.Y, err = curve.DecompressPoint(pubkey.X, ybit)
		if err != nil {
			return nil, err
		}

	default: // wrong!
		return nil, fmt.Errorf("invalid pub key length %d", len(pubKeyStr))
	}

	return &pubkey, nil
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}
