package wallet

import (
	ecdsa2 "crypto/ecdsa"
	"encoding/hex"
	"github.com/git-yongge/ethgo/jsonrpc"
	"math/big"
	"testing"

	"github.com/git-yongge/ethgo"
	"github.com/git-yongge/ethgo/crypto-ecdsa"
	"github.com/stretchr/testify/assert"
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
	signer1 := NewEIP155Signer(97)

	from := ethgo.HexToAddress("0x5573143eBA235545BE5548E1107dD7B92713EF18")
	to := ethgo.HexToAddress("0x89055606E4DD8F04C3014903C202AfF35691D2BA")
	hexprv := "7ccd2ecc25ab5332f5f7a564d7b785f86309c3597ac3ab45030c3bb4dfd67e5e"
	eckey, err := ecdsa.Hex2Privkey(hexprv)
	if err != nil {
		t.Fatal(err)
	}

	c, _ := jsonrpc.NewClient("https://data-seed-prebsc-1-s1.binance.org:8545/")
	nonce, err := c.Eth().GetNonce(from, ethgo.Latest)
	if err != nil {
		t.Fatal("GetNonce err", err)
	}
	t.Log("get nonce", nonce)

	ecdsaKey := new(ecdsa2.PrivateKey)
	ecdsaKey.PublicKey = eckey.PublicKey
	ecdsaKey.D = eckey.D
	key := NewKey(ecdsaKey)
	//hexData := "40c10f19000000000000000000000000d615c42cf7856e0634404b7584ef8fcd6cc9b8960000000000000000000000000000000000000000000000000000000000000001"
	//data, err := hex.DecodeString(hexData)
	//if err != nil {
	//	t.Fatal(err)
	//}

	txn := &ethgo.Transaction{
		Nonce:    nonce,
		To:       &to,
		Value:    big.NewInt(1000000000),
		Gas:      234723,      // 394e3
		GasPrice: 10000000000, // 12a05f200
	}
	t.Log("input==>", hex.EncodeToString(txn.Input))
	signtxn, err := signer1.SignTx(txn, key)
	if err != nil {
		t.Fatal("signtx err", err)
	}

	b, _ := signtxn.MarshalRLPTo(nil)
	t.Log("0x" + hex.EncodeToString(b))

	signer2 := NewEIP155Signer(97)
	from2, err := signer2.RecoverSender(txn)
	if err != nil {
		t.Fatal("recover err", err)
	}
	t.Log("recover==>", from2.String())
}
