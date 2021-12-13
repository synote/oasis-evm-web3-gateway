package indexer

import (
	"encoding/hex"
	"math/big"

	"github.com/fxamacker/cbor/v2"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/client"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/types"

	"github.com/starfishlabs/oasis-evm-web3-gateway/filters"
	"github.com/starfishlabs/oasis-evm-web3-gateway/model"
	"github.com/starfishlabs/oasis-evm-web3-gateway/storage"
)

var (
	defaultValidatorAddr = "0x0000000000000000000000000000000088888888"
	defaultGasLimit      = 21000 * 1000
)

// Log is the Oasis Log.
type Log struct {
	Address common.Address
	Topics  []common.Hash
	Data    []byte
}

// Logs2EthLogs converts logs in db to ethereum logs.
func Logs2EthLogs(logs []*Log, round uint64, blockHash, txHash common.Hash, txIndex uint32) []*ethtypes.Log {
	ethLogs := []*ethtypes.Log{}
	for i := range logs {
		ethLog := &ethtypes.Log{
			Address:     logs[i].Address,
			Topics:      logs[i].Topics,
			Data:        logs[i].Data,
			BlockNumber: round,
			TxHash:      txHash,
			TxIndex:     uint(txIndex),
			BlockHash:   blockHash,
			Index:       uint(i),
			Removed:     false,
		}
		ethLogs = append(ethLogs, ethLog)
	}
	return ethLogs
}

// convertToEthFormat converts oasis block to ethereum block.
func convertToEthFormat(
	block *block.Block,
	transactions ethtypes.Transactions,
	logsBloom ethtypes.Bloom,
	txsStatus []uint8,
	results []types.CallResult,
	gas uint64,
) (*model.Block, []*model.Transaction, []*model.Receipt, error) {
	encoded := block.Header.EncodedHash()
	bhash := common.HexToHash(encoded.Hex()).String()
	bprehash := block.Header.PreviousHash.Hex()
	bshash := block.Header.StateRoot.Hex()
	bloomData, _ := logsBloom.MarshalText()
	baseFee := big.NewInt(10)
	number := big.NewInt(0)
	number.SetUint64(block.Header.Round)
	var btxHash string
	if len(transactions) == 0 {
		btxHash = ethtypes.EmptyRootHash.Hex()
	} else {
		btxHash = block.Header.IORoot.Hex()
	}

	innerHeader := &model.Header{
		ParentHash:  bprehash,
		UncleHash:   ethtypes.EmptyUncleHash.Hex(),
		Coinbase:    common.HexToAddress(defaultValidatorAddr).Hex(),
		Root:        bshash,
		TxHash:      btxHash,
		ReceiptHash: ethtypes.EmptyRootHash.Hex(),
		Bloom:       string(bloomData),
		Difficulty:  big.NewInt(0).String(),
		Number:      number.String(),
		GasLimit:    uint64(defaultGasLimit),
		GasUsed:     gas,
		Time:        uint64(block.Header.Timestamp),
		Extra:       "",
		MixDigest:   "",
		Nonce:       ethtypes.BlockNonce{}.Uint64(),
		BaseFee:     baseFee.String(),
	}

	innerTxs := []*model.Transaction{}
	innerReceipts := []*model.Receipt{}
	cumulativeGasUsed := uint64(0)
	for idx, ethTx := range transactions {
		v, r, s := ethTx.RawSignatureValues()
		signer := ethtypes.LatestSignerForChainID(ethTx.ChainId())
		from, _ := signer.Sender(ethTx)
		ethAccList := ethTx.AccessList()
		accList := []model.AccessTuple{}
		for _, ethAcc := range ethAccList {
			keys := []string{}
			for _, ethStorageKey := range ethAcc.StorageKeys {
				keys = append(keys, ethStorageKey.Hex())
			}
			acc := model.AccessTuple{
				Address:     ethAcc.Address.Hex(),
				StorageKeys: keys,
			}
			accList = append(accList, acc)
		}
		tx := &model.Transaction{
			Hash:       ethTx.Hash().Hex(),
			Type:       ethTx.Type(),
			ChainID:    ethTx.ChainId().String(),
			Status:     uint(txsStatus[idx]),
			BlockHash:  bhash,
			Round:      number.Uint64(),
			Index:      uint32(idx),
			Gas:        ethTx.Gas(),
			GasPrice:   ethTx.GasPrice().String(),
			GasTipCap:  ethTx.GasTipCap().String(),
			GasFeeCap:  ethTx.GasFeeCap().String(),
			Nonce:      ethTx.Nonce(),
			FromAddr:   from.Hex(),
			Value:      ethTx.Value().String(),
			Data:       hex.EncodeToString(ethTx.Data()),
			AccessList: accList,
			V:          v.String(),
			R:          r.String(),
			S:          s.String(),
		}
		to := ethTx.To()
		if to == nil {
			tx.ToAddr = ""
		} else {
			tx.ToAddr = to.Hex()
		}
		innerTxs = append(innerTxs, tx)

		// receipts
		cumulativeGasUsed += tx.Gas
		receipt := &model.Receipt{
			Status:            uint(txsStatus[idx]),
			CumulativeGasUsed: cumulativeGasUsed,
			LogsBloom:         hex.EncodeToString(bloomData),
			TransactionHash:   ethTx.Hash().Hex(),
			BlockHash:         bhash,
			GasUsed:           ethTx.Gas(),
			Type:              uint(ethTx.Type()),
			Round:             block.Header.Round,
			TransactionIndex:  uint64(idx),
			FromAddr:          tx.FromAddr,
			ToAddr:            tx.ToAddr,
		}
		if len(receipt.Logs) == 0 {
			receipt.Logs = []*model.Log{}
		}
		if tx.ToAddr == "" && results[idx].IsSuccess() {
			var out []byte
			if err := cbor.Unmarshal(results[idx].Ok, &out); err != nil {
				return nil, nil, nil, err
			}
			receipt.ContractAddress = common.BytesToAddress(out).Hex()
		}
		innerReceipts = append(innerReceipts, receipt)
	}

	innerBlock := &model.Block{
		Hash:         bhash,
		Round:        number.Uint64(),
		Header:       innerHeader,
		Uncles:       []*model.Header{},
		Transactions: innerTxs,
	}

	return innerBlock, innerTxs, innerReceipts, nil
}

// StoreBlockData parses oasis block and stores in db.
func (ib *indexBackend) StoreBlockData(oasisBlock *block.Block, txResults []*client.TransactionWithResults) error {
	encoded := oasisBlock.Header.EncodedHash()
	bhash := common.HexToHash(encoded.Hex())
	blockNum := oasisBlock.Header.Round

	ethTxs := ethtypes.Transactions{}
	logs := []*ethtypes.Log{}
	txsStatus := []uint8{}
	results := []types.CallResult{}
	var gasUsed uint64
	var dbLogs []*model.Log

	// Decode tx and get logs
	for txIndex, item := range txResults {
		oasisTx := item.Tx
		if len(oasisTx.AuthProofs) != 1 || oasisTx.AuthProofs[0].Module != "evm.ethereum.v0" {
			// Skip non-Ethereum transactions.
			continue
		}

		// Extract raw Ethereum transaction for further processing.
		rawEthTx := oasisTx.Body
		// Decode the Ethereum transaction.
		ethTx := &ethtypes.Transaction{}
		err := rlp.DecodeBytes(rawEthTx, ethTx)
		if err != nil {
			ib.logger.Error("Failed to decode UnverifiedTransaction", "height", blockNum, "index", txIndex, "err", err)
			return err
		}

		status := uint8(0)
		if txResults[txIndex].Result.IsSuccess() {
			status = uint8(ethtypes.ReceiptStatusSuccessful)
		} else {
			status = uint8(ethtypes.ReceiptStatusFailed)
		}
		txsStatus = append(txsStatus, status)
		results = append(results, item.Result)

		gasUsed += ethTx.Gas()
		ethTxs = append(ethTxs, ethTx)

		var oasisLogs []*Log
		resEvents := item.Events
		for eventIndex, event := range resEvents {
			if event.Code == 1 {
				var logs []*Log
				if err = cbor.Unmarshal(event.Value, &logs); err != nil {
					ib.logger.Debug("Failed to unmarshal event value, trying legacy format next", "index", eventIndex, "err", err)

					// Emerald events value format changed in https://github.com/oasisprotocol/oasis-sdk/pull/675.
					// Try the legacy format in case the new format unmarshalling failed.
					var log Log
					if lerr := cbor.Unmarshal(event.Value, &log); lerr != nil {
						ib.logger.Error("Failed to unmarshal event value", "index", eventIndex, "legacy_err", lerr, "err", err)
						// The legacy fallback failed, likely the event not in legacy format, return the original unmarshal error.
						return err
					}
					oasisLogs = append(oasisLogs, &log)
					continue
				}
				oasisLogs = append(oasisLogs, logs...)
			}
		}
		logs = append(logs, Logs2EthLogs(oasisLogs, blockNum, bhash, ethTx.Hash(), uint32(txIndex))...)
		dbLogs = eth2DbLogs(logs)
	}

	// Get convert block, transactions and receipts.
	logsBloom := ethtypes.BytesToBloom(ethtypes.LogsBloom(logs))
	blk, txs, receipts, err := convertToEthFormat(oasisBlock, ethTxs, logsBloom, txsStatus, results, gasUsed)
	if err != nil {
		ib.logger.Debug("Failed to ConvertToEthBlock", "height", blockNum, "err", err)
		return err
	}

	// Send event to event system
	chainEvent := filters.ChainEvent{
		Block: blk,
		Hash:  bhash,
		Logs:  dbLogs,
	}
	ib.subscribe.ChainChan() <- chainEvent
	ib.logger.Debug("Send chain event to event system", "height", blockNum)

	return ib.storage.RunInTransaction(ib.ctx, func(s storage.Storage) error {
		// Store txs.
		for _, tx := range txs {
			err = s.Upsert(tx)
			if err != nil {
				return err
			}
		}

		// Store receipts.
		for _, receipt := range receipts {
			err = s.Upsert(receipt)
			if err != nil {
				return err
			}
		}

		// Store logs.
		for _, log := range eth2DbLogs(logs) {
			if err = s.Upsert(log); err != nil {
				ib.logger.Error("Failed to store logs", "height", blockNum, "log", log, "err", err)
				return err
			}
		}

		// Store block.
		return s.Upsert(blk)
	})
}

// eth2DbLogs converts ethereum log to model log.
func eth2DbLogs(ethLogs []*ethtypes.Log) []*model.Log {
	res := []*model.Log{}

	for _, log := range ethLogs {
		topics := []string{}
		for _, tp := range log.Topics {
			topics = append(topics, tp.Hex())
		}

		dbLog := &model.Log{
			Address:   log.Address.Hex(),
			Topics:    topics,
			Data:      hex.EncodeToString(log.Data),
			Round:     log.BlockNumber,
			BlockHash: log.BlockHash.Hex(),
			TxHash:    log.TxHash.Hex(),
			TxIndex:   log.TxIndex,
			Index:     log.Index,
			Removed:   log.Removed,
		}

		res = append(res, dbLog)
	}

	return res
}
