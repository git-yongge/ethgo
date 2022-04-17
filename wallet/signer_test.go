package wallet

import (
	ecdsa2 "crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/umbracle/ethgo"
	"github.com/umbracle/ethgo/crypto-ecdsa"
)

func TestSigner_EIP1155(t *testing.T) {
	signer1 := NewEIP155Signer(1337)

	addr0 := ethgo.Address{0x1}
	key, err := GenerateKey()
	assert.NoError(t, err)

	txn := &ethgo.Transaction{
		To:       &addr0,
		Value:    big.NewInt(10),
		GasPrice: 0,
	}
	txn, err = signer1.SignTx(txn, key)
	assert.NoError(t, err)

	from, err := signer1.RecoverSender(txn)
	assert.NoError(t, err)
	assert.Equal(t, from, key.addr)

	/*
		// try to use a signer with another chain id
		signer2 := NewEIP155Signer(2)
		from2, err := signer2.RecoverSender(txn)
		assert.NoError(t, err)
		assert.NotEqual(t, from, from2)
	*/
}

func TestKey_Sign(t *testing.T) {
	signer1 := NewEIP155Signer(80001)

	from := ethgo.HexToAddress("0xD615c42CF7856e0634404B7584EF8FcD6CC9B896")
	to := ethgo.HexToAddress("0x0079fbaceb8f886009f55639b5506b5de4ed75cb")
	hexprv := "22a90d9711350a0b7c7c697ccb26dd1224ffbf16f6430220d28f0a30235fb01e"
	eckey, err := ecdsa.Hex2Privkey(hexprv)
	if err != nil {
		t.Fatal(err)
	}

	ecdsaKey := new(ecdsa2.PrivateKey)
	ecdsaKey.PublicKey = eckey.PublicKey
	ecdsaKey.D = eckey.D
	key := NewKey(ecdsaKey)
	hexData := "40c10f19000000000000000000000000d615c42cf7856e0634404b7584ef8fcd6cc9b8960000000000000000000000000000000000000000000000000000000000000001"
	data, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatal(err)
	}
	txn := &ethgo.Transaction{
		Nonce:    50,
		From:     from,
		To:       &to,
		Value:    big.NewInt(0),
		Gas:      234723,     // 394e3
		GasPrice: 5000000000, // 12a05f200
		Input:    data,
	}
	fmt.Println("input==>", hex.EncodeToString(txn.Input))
	signtxn, err := signer1.SignTx(txn, key)
	if err != nil {
		t.Fatal("signtx err", err)
	}

	b, _ := signtxn.MarshalRLPTo(nil)
	t.Log("0x" + hex.EncodeToString(b))

	signer2 := NewEIP155Signer(80001)
	from2, err := signer2.RecoverSender(txn)
	if err != nil {
		t.Fatal("recover err", err)
	}
	t.Log("recover==>", from2.String())
}
