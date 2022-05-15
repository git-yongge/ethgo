package ecdsa

import (
	"encoding/hex"
	"github.com/git-yongge/ethgo/crypto/sha3"
	"testing"
)

func TestGenerateKey(t *testing.T) {

	priv, _ := GenerateKey()
	t.Log("priv: ", priv.Hex())
	t.Log("pub: ", priv.Pubkey().ToCompressHex())
	t.Log("pub: ", priv.Pubkey().Hex())

	msg := []byte("hello")
	hash := sha3.Keccak256(msg)
	t.Log("hash: ", hex.EncodeToString(hash))

	signature, err := priv.Sign(hash)
	if err != nil {
		t.Fatal("Sign err：", err)
	}
	t.Log("signature: ", signature)

	verify := signature.Verify(hash, priv.Pubkey())
	t.Log("verify：", verify)
}

func TestSignCompact(t *testing.T) {

	hash := "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
	hashByte, _ := hex.DecodeString(hash)
	privHex := "22861a2fbd5c05cf30e86a3370bbbc7d122e83aa4b2530629d14ae6ada41cc7b"
	priv, _ := Hex2Privkey(privHex)
	t.Log("pub: ", priv.Pubkey().Hex())

	// 签名
	signB, err := SignCompact(S256(), priv, hashByte, true)
	if err != nil {
		t.Fatal("SignCompact err: ", err)
	}
	t.Log("signature2: ", hex.EncodeToString(signB))

	// 签名
	signB2, err := SignCompact(S256(), priv, hashByte, false)
	if err != nil {
		t.Fatal("SignCompact err: ", err)
	}
	t.Log("signature3: ", hex.EncodeToString(signB2))

	// 验签， isCompressKey == true 的 SignCompact
	pub, ok, err := RecoverCompact(S256(), signB, hashByte)
	if err != nil {
		t.Fatal("RecoverCompact err: ", err)
	}
	if ok == false {
		t.Fatal("RecoverCompact failed， ", ok)
	}
	t.Log("success：", pub.Hex())
}

func TestRecoverCompact(t *testing.T) {
	signHex := "1f2a3f8181094733ae467c28910690d9019f2b2a2e63a86b57023dfda8bffb2486215445a4bbe4232a16b2dd3623c909bd62fc564d20f4d71f7f34b3251ed2ea9d"
	signB, _ := hex.DecodeString(signHex)

	hash := "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
	hashByte, _ := hex.DecodeString(hash)

	pub, ok, err := RecoverCompact(S256(), signB, hashByte)
	if err != nil || ok == false {
		t.Fatal(ok, err)
	}
	t.Log(pub.Hex())

}

func TestGenerateTopic(t *testing.T) {
	m := sha3.MethodSig("withdrawTxFee")
	t.Log(hex.EncodeToString(m))
	t.Log(GenerateTopic("withdrawTxFee()"))
	t.Log(GenerateTopic("transfer(address,uint256)"))
}
