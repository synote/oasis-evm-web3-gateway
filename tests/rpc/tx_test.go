package rpc

import (
	"context"
	_ "embed"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/require"
)

// We store the compiled EVM bytecode for the SimpleSolEVMTest in a separate
// file (in hex) to preserve readability of this file.
//go:embed contracts/evm_sol_test_compiled.hex
var evmSolTestCompiledHex string

// We store the compiled EVM bytecode for the SimpleERC20EVMTest in a separate
// file (in hex) to preserve readability of this file.
//go:embed contracts/evm_erc20_test_compiled.hex
var evmERC20TestCompiledHex string

func waitTransaction(ctx context.Context, ec *ethclient.Client, txhash common.Hash) (*types.Receipt, error) {
	queryTicker := time.NewTicker(time.Second)
	defer queryTicker.Stop()

	for {
		receipt, err := ec.TransactionReceipt(ctx, txhash)
		if receipt != nil {
			return receipt, nil
		}
		if err != nil {
			return nil, err
		}
		// Wait for the next round.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-queryTicker.C:
		}
	}
}

func testContractCreation(t *testing.T, value *big.Int) {
	url, err := w3.GetHTTPEndpoint()
	require.NoError(t, err)
	ec, _ := ethclient.Dial(url)

	code := common.FromHex(strings.TrimSpace(evmSolTestCompiledHex))

	chainID, err := ec.ChainID(context.Background())
	require.Nil(t, err, "get chainid")

	nonce, err := ec.NonceAt(context.Background(), common.HexToAddress(daveEVMAddr), nil)
	require.Nil(t, err, "get nonce failed")

	// Create transaction
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		Value:    value,
		Gas:      1000000,
		GasPrice: big.NewInt(2),
		Data:     code,
	})
	signer := types.LatestSignerForChainID(chainID)
	signature, err := crypto.Sign(signer.Hash(tx).Bytes(), daveKey)
	require.Nil(t, err, "sign tx")

	signedTx, err := tx.WithSignature(signer, signature)
	require.Nil(t, err, "pack tx")

	err = ec.SendTransaction(context.Background(), signedTx)
	require.Nil(t, err, "send transaction failed")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	receipt, err := waitTransaction(ctx, ec, signedTx.Hash())
	if err != nil {
		t.Errorf("get receipt failed: %s", err)
		return
	}
	// t.Logf("Contract address: %s", receipt.ContractAddress)

	require.Equal(t, receipt.Status, uint64(1))
}

func TestContractCreation(t *testing.T) {
	testContractCreation(t, big.NewInt(0))
}

func TestContractFailCreation(t *testing.T) {
	testContractCreation(t, big.NewInt(1))
}

func TestEth_EstimateGas(t *testing.T) {
	ec := localClient()
	code := common.FromHex(strings.TrimSpace(evmSolTestCompiledHex))

	chainID, err := ec.ChainID(context.Background())
	require.Nil(t, err, "get chainid")

	nonce, err := ec.NonceAt(context.Background(), common.HexToAddress(daveEVMAddr), nil)
	require.Nil(t, err, "get nonce failed")

	// Build call args for estimate gas
	msg := ethereum.CallMsg{
		From:  common.HexToAddress(daveEVMAddr),
		Value: big.NewInt(0),
		Data:  code,
	}
	gas, err := ec.EstimateGas(context.Background(), msg)
	require.Nil(t, err, "gas estimation")
	t.Logf("estimate gas: %v", gas)

	// Create transaction
	tx := types.NewContractCreation(nonce, big.NewInt(0), gas, big.NewInt(2), code)
	signer := types.LatestSignerForChainID(chainID)
	signature, err := crypto.Sign(signer.Hash(tx).Bytes(), daveKey)
	require.Nil(t, err, "sign tx")

	signedTx, err := tx.WithSignature(signer, signature)
	require.Nil(t, err, "pack tx")

	err = ec.SendTransaction(context.Background(), signedTx)
	require.Nil(t, err, "send transaction failed")
}

func TestEth_GetCode(t *testing.T) {
	url, err := w3.GetHTTPEndpoint()
	require.NoError(t, err)
	ec, _ := ethclient.Dial(url)

	code := common.FromHex(strings.TrimSpace(evmSolTestCompiledHex))

	chainID, err := ec.ChainID(context.Background())
	require.Nil(t, err, "get chainid")

	nonce, err := ec.NonceAt(context.Background(), common.HexToAddress(daveEVMAddr), nil)
	require.Nil(t, err, "get nonce failed")

	// Create transaction
	tx := types.NewContractCreation(nonce, big.NewInt(0), 1000000, big.NewInt(2), code)
	signer := types.LatestSignerForChainID(chainID)
	signature, err := crypto.Sign(signer.Hash(tx).Bytes(), daveKey)
	require.Nil(t, err, "sign tx")

	signedTx, err := tx.WithSignature(signer, signature)
	require.Nil(t, err, "pack tx")

	err = ec.SendTransaction(context.Background(), signedTx)
	require.Nil(t, err, "send transaction failed")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	receipt, err := waitTransaction(ctx, ec, signedTx.Hash())
	if err != nil {
		t.Errorf("get receipt failed: %s", err)
		return
	}
	t.Logf("Contract address: %s", receipt.ContractAddress)

	require.Equal(t, uint64(1), receipt.Status)

	storedCode, err := ec.CodeAt(context.Background(), receipt.ContractAddress, nil)
	require.Nil(t, err, "get code")
	require.NotEmpty(t, storedCode)
}

func TestEth_Call(t *testing.T) {
	abidata := `
		[
			{
				"inputs": [],
				"stateMutability": "nonpayable",
				"type": "constructor"
			},
			{
				"inputs": [],
				"name": "name",
				"outputs": [
					{
						"internalType": "string",
						"name": "",
						"type": "string"
					}
				],
				"stateMutability": "view",
				"type": "function"
			}
		]
	`
	testabi, _ := abi.JSON(strings.NewReader(abidata))

	url, err := w3.GetHTTPEndpoint()
	require.NoError(t, err)
	ec, _ := ethclient.Dial(url)

	code := common.FromHex(strings.TrimSpace(evmSolTestCompiledHex))

	chainID, err := ec.ChainID(context.Background())
	require.Nil(t, err, "get chainid")

	nonce, err := ec.NonceAt(context.Background(), common.HexToAddress(daveEVMAddr), nil)
	require.Nil(t, err, "get nonce failed")

	// Create transaction
	tx := types.NewContractCreation(nonce, big.NewInt(0), 1000000, big.NewInt(2), code)
	signer := types.LatestSignerForChainID(chainID)
	signature, err := crypto.Sign(signer.Hash(tx).Bytes(), daveKey)
	require.Nil(t, err, "sign tx")

	signedTx, err := tx.WithSignature(signer, signature)
	require.Nil(t, err, "pack tx")

	err = ec.SendTransaction(context.Background(), signedTx)
	require.Nil(t, err, "send transaction failed")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	receipt, err := waitTransaction(ctx, ec, signedTx.Hash())
	if err != nil {
		t.Errorf("get receipt failed: %s", err)
		return
	}
	// t.Logf("Contract address: %s", receipt.ContractAddress)

	require.Equal(t, receipt.Status, uint64(1))

	calldata, err := testabi.Pack("name")
	if err != nil {
		t.Error(err)
	}
	t.Logf("calldata: %x", calldata)

	msg := ethereum.CallMsg{
		To:   &receipt.ContractAddress,
		Data: calldata,
	}

	out, err := ec.CallContract(context.Background(), msg, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Logf("contract call return: %x", out)

	ret, err := testabi.Unpack("name", out)
	require.Nil(t, err)
	require.Equal(t, "test", ret[0])
}

// TestERC20 deploy erc20 with no constructor.
//
//   pragma solidity ^0.8.0;
//   import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
//   contract TestToken is ERC20 {
// 	   constructor() ERC20("Test", "TST") public {
// 	     _mint(msg.sender, 1000000 * (10 ** uint256(decimals())));
// 	   }
//   }
func TestERC20(t *testing.T) {
	testabi, _ := abi.JSON(strings.NewReader(erc20abi))

	url, err := w3.GetHTTPEndpoint()
	require.NoError(t, err)
	ec, _ := ethclient.Dial(url)

	code := common.FromHex(strings.TrimSpace(evmERC20TestCompiledHex))

	chainID, err := ec.ChainID(context.Background())
	require.Nil(t, err, "get chainid")

	nonce, err := ec.NonceAt(context.Background(), common.HexToAddress(daveEVMAddr), nil)
	require.Nil(t, err, "get nonce failed")

	// Deploy ERC20 contract
	tx := types.NewContractCreation(nonce, big.NewInt(0), 1000000, big.NewInt(2), code)
	signer := types.LatestSignerForChainID(chainID)
	signature, err := crypto.Sign(signer.Hash(tx).Bytes(), daveKey)
	require.Nil(t, err, "sign tx")

	signedTx, err := tx.WithSignature(signer, signature)
	require.Nil(t, err, "pack tx")

	err = ec.SendTransaction(context.Background(), signedTx)
	require.Nil(t, err, "send transaction failed")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	receipt, err := waitTransaction(ctx, ec, signedTx.Hash())
	if err != nil {
		t.Errorf("get receipt failed: %s", err)
		return
	}
	require.Equal(t, uint64(1), receipt.Status)
	tokenAddr := receipt.ContractAddress
	t.Logf("ERC20 address: %s", tokenAddr.Hex())

	// Make transfer token transaction
	nonce, err = ec.NonceAt(context.Background(), common.HexToAddress(daveEVMAddr), nil)
	require.Nil(t, err, "get nonce failed")
	transferCall, err := testabi.Pack("transfer", common.Address{1}, big.NewInt(10))
	if err != nil {
		t.Error(err)
	}

	tx = types.NewTransaction(nonce, tokenAddr, big.NewInt(0), 1000000, big.NewInt(2), transferCall)
	signer = types.LatestSignerForChainID(chainID)
	signature, err = crypto.Sign(signer.Hash(tx).Bytes(), daveKey)
	require.Nil(t, err, "sign tx")
	signedTx, err = tx.WithSignature(signer, signature)
	require.Nil(t, err, "pack tx")
	err = ec.SendTransaction(context.Background(), signedTx)
	require.Nil(t, err, "send transaction failed")

	receipt, err = waitTransaction(context.Background(), ec, signedTx.Hash())
	if err != nil {
		t.Errorf("get receipt failed: %s", err)
		return
	}
	require.Equal(t, uint64(1), receipt.Status)

	// Get balance of token receiver
	balanceOfCall, err := testabi.Pack("balanceOf", common.Address{1})
	if err != nil {
		t.Error(err)
	}
	msg := ethereum.CallMsg{
		To:   &tokenAddr,
		Data: balanceOfCall,
	}
	out, err := ec.CallContract(context.Background(), msg, nil)
	require.Nil(t, err)
	t.Logf("contract call return: %x", out)

	ret, err := testabi.Unpack("balanceOf", out)
	require.Nil(t, err)
	require.Equal(t, big.NewInt(10), ret[0])
}
