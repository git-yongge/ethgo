package examples

import (
	"fmt"

	"github.com/git-yongge/ethgo/abi"
	"github.com/git-yongge/ethgo/contract"
)

func contractDeploy() {
	abiContract, err := abi.NewABIFromList([]string{})
	handleErr(err)

	// bytecode of the contract
	bin := []byte{}

	txn, err := contract.DeployContract(abiContract, bin, []interface{}{})
	handleErr(err)

	err = txn.Do()
	handleErr(err)

	receipt, err := txn.Wait()
	handleErr(err)

	fmt.Printf("Contract: %s", receipt.ContractAddress)
}
