package indexer

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/starfishlabs/oasis-evm-web3-gateway/filters"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/client"

	"github.com/starfishlabs/oasis-evm-web3-gateway/model"
	"github.com/starfishlabs/oasis-evm-web3-gateway/storage"
)

var ErrGetLastRetainedRound = errors.New("get last retained round error in db")

// Result is a query result.
type Result struct {
	// TxHash is the hash of the matched transaction.
	TxHash hash.Hash
	// TxIndex is the index of the matched transaction within the block.
	TxIndex uint32
}

// Results are query results.
//
// Map key is the round number and value is a list of transaction hashes
// that match the query.
type Results map[uint64][]Result

// BackendFactory is the indexer backend factory interface.
type BackendFactory func(ctx context.Context, runtimeID common.Namespace, storage storage.Storage, sb filters.SubscribeBackend) (Backend, error)

// QueryableBackend is the read-only indexer backend interface.
type QueryableBackend interface {
	// QueryBlockRound queries block round by block hash.
	QueryBlockRound(blockHash ethcommon.Hash) (uint64, error)

	// QueryBlockHash queries block hash by round.
	QueryBlockHash(round uint64) (ethcommon.Hash, error)

	// QueryTransactionRef returns block hash, round and index of the transaction.
	QueryTransactionRef(ethTxHash string) (*model.TransactionRef, error)

	// QueryLastIndexedRound query continues indexed block round.
	QueryLastIndexedRound() (uint64, error)

	// QueryLastRetainedRound query the minimum round not pruned.
	QueryLastRetainedRound() (uint64, error)

	// QueryTransaction queries ethereum transaction by hash.
	QueryTransaction(ethTxHash ethcommon.Hash) (*model.Transaction, error)
}

// GetEthInfoBackend is a backend for handling ethereum data.
type GetEthInfoBackend interface {
	GetBlockByRound(round uint64) (*model.Block, error)
	GetBlockByHash(blockHash ethcommon.Hash) (*model.Block, error)
	GetBlockTransactionCountByRound(round uint64) (int, error)
	GetBlockTransactionCountByHash(blockHash ethcommon.Hash) (int, error)
	GetTransactionByBlockHashAndIndex(blockHash ethcommon.Hash, txIndex int) (*model.Transaction, error)
	GetTransactionReceipt(txHash ethcommon.Hash) (map[string]interface{}, error)
	BlockNumber() (uint64, error)
	GetLogs(startRound, endRound uint64) ([]*model.Log, error)
}

// Backend is the indexer backend interface.
type Backend interface {
	QueryableBackend
	GetEthInfoBackend

	// Index indexes a block.
	Index(
		oasisBlock *block.Block,
		txResults []*client.TransactionWithResults,
	) error

	// Prune removes indexed data for rounds equal to or earlier than the passed round.
	Prune(round uint64) error

	// UpdateLastIndexedRound updates the last indexed round metadata.
	UpdateLastIndexedRound(round uint64) error

	// Close performs backend-specific cleanup. The backend should not be used anymore after calling
	// this method.
	Close()
}

type indexBackend struct {
	ctx context.Context

	runtimeID common.Namespace
	logger    *logging.Logger
	storage   storage.Storage
	subscribe filters.SubscribeBackend
}

// Index indexes oasis block.
func (ib *indexBackend) Index(oasisBlock *block.Block, txResults []*client.TransactionWithResults) error {
	round := oasisBlock.Header.Round
	blockHash := ethcommon.HexToHash(oasisBlock.Header.EncodedHash().Hex())

	// oasis block round <-> oasis block hash, maybe remove later
	blockRef := &model.BlockRef{
		Round: oasisBlock.Header.Round,
		Hash:  blockHash.String(),
	}
	if err := ib.storage.Upsert(blockRef); err != nil {
		return err
	}

	// oasis block -> eth block, store eth block
	err := ib.StoreBlockData(oasisBlock, txResults)
	if err != nil {
		ib.logger.Error("generateEthBlock failed", "err", err)
		return err
	}

	ib.logger.Info("indexed block", "round", round)

	return nil
}

// UpdateLastIndexedRound updates the last indexed round.
func (ib *indexBackend) UpdateLastIndexedRound(round uint64) error {
	return ib.storeIndexedRound(round)
}

// Prune prunes data in db.
func (ib *indexBackend) Prune(round uint64) error {
	if err := ib.storeLastRetainedRound(round); err != nil {
		return err
	}

	if err := ib.storage.Delete(new(model.BlockRef), round); err != nil {
		return err
	}

	if err := ib.storage.Delete(new(model.Block), round); err != nil {
		return err
	}

	if err := ib.storage.Delete(new(model.Log), round); err != nil {
		return err
	}

	if err := ib.storage.Delete(new(model.Transaction), round); err != nil {
		return err
	}

	if err := ib.storage.Delete(new(model.TransactionRef), round); err != nil {
		return err
	}

	if err := ib.storage.Delete(new(model.Receipt), round); err != nil {
		return err
	}

	return nil
}

// blockNumberFromRound converts a round to a blocknumber.
func (ib *indexBackend) blockNumberFromRound(round uint64) (number uint64, err error) {
	switch round {
	case client.RoundLatest:
		number, err = ib.BlockNumber()
	default:
		number = round
	}
	return
}

// QueryBlockRound returns block number for the provided hash.
func (ib *indexBackend) QueryBlockRound(blockHash ethcommon.Hash) (uint64, error) {
	round, err := ib.storage.GetBlockRound(blockHash.String())
	if err != nil {
		ib.logger.Error("Can't find matched block")
		return 0, err
	}

	return round, nil
}

// QueryBlockHash returns the block hash for the provided round.
func (ib *indexBackend) QueryBlockHash(round uint64) (ethcommon.Hash, error) {
	var blockHash string
	var err error
	switch round {
	case client.RoundLatest:
		blockHash, err = ib.storage.GetLatestBlockHash()
	default:
		blockHash, err = ib.storage.GetBlockHash(round)
	}

	if err != nil {
		ib.logger.Error("failed to query block hash", "err", err)
		return ethcommon.Hash{}, err
	}
	return ethcommon.HexToHash(blockHash), nil
}

// storeIndexedRound stores indexed round.
func (ib *indexBackend) storeIndexedRound(round uint64) error {
	r := &model.IndexedRoundWithTip{
		Tip:   model.Continues,
		Round: round,
	}

	return ib.storage.Upsert(r)
}

// QueryLastIndexedRound returns the last indexed round.
func (ib *indexBackend) QueryLastIndexedRound() (uint64, error) {
	indexedRound, err := ib.storage.GetLastIndexedRound()
	if err != nil {
		return 0, err
	}

	return indexedRound, nil
}

// storeLastRetainedRound stores the last retained round.
func (ib *indexBackend) storeLastRetainedRound(round uint64) error {
	r := &model.IndexedRoundWithTip{
		Tip:   model.LastRetained,
		Round: round,
	}

	return ib.storage.Upsert(r)
}

// QueryLastRetainedRound returns the last retained round.
func (ib *indexBackend) QueryLastRetainedRound() (uint64, error) {
	lastRetainedRound, err := ib.storage.GetLastRetainedRound()
	if err != nil {
		return 0, ErrGetLastRetainedRound
	}
	return lastRetainedRound, nil
}

// QueryTransaction returns transaction by transaction hash.
func (ib *indexBackend) QueryTransaction(txHash ethcommon.Hash) (*model.Transaction, error) {
	tx, err := ib.storage.GetTransaction(txHash.String())
	if err != nil {
		return nil, err
	}
	return tx, nil
}

// QueryTransactionRef returns TransactionRef by transaction hash.
func (ib *indexBackend) QueryTransactionRef(hash string) (*model.TransactionRef, error) {
	return ib.storage.GetTransactionRef(hash)
}

// GetBlockByRound returns a block for the provided round.
func (ib *indexBackend) GetBlockByRound(round uint64) (*model.Block, error) {
	blockNumber, err := ib.blockNumberFromRound(round)
	if err != nil {
		return nil, err
	}
	blk, err := ib.storage.GetBlockByNumber(blockNumber)
	if err != nil {
		return nil, err
	}

	return blk, nil
}

// GetBlockByHash returns a block by bock hash.
func (ib *indexBackend) GetBlockByHash(blockHash ethcommon.Hash) (*model.Block, error) {
	blk, err := ib.storage.GetBlockByHash(blockHash.String())
	if err != nil {
		return nil, err
	}

	return blk, nil
}

// GetBlockTransactionCountByRound returns the count of block transactions for the provided round.
func (ib *indexBackend) GetBlockTransactionCountByRound(round uint64) (int, error) {
	blockNumber, err := ib.blockNumberFromRound(round)
	if err != nil {
		return 0, err
	}
	return ib.storage.GetBlockTransactionCountByNumber(blockNumber)
}

// GetBlockTransactionCountByHash returns the count of block transactions by block hash.
func (ib *indexBackend) GetBlockTransactionCountByHash(blockHash ethcommon.Hash) (int, error) {
	return ib.storage.GetBlockTransactionCountByHash(blockHash.String())
}

// GetTransactionByBlockHashAndIndex returns transaction by the block hash and transaction index.
func (ib *indexBackend) GetTransactionByBlockHashAndIndex(blockHash ethcommon.Hash, txIndex int) (*model.Transaction, error) {
	return ib.storage.GetBlockTransaction(blockHash.String(), txIndex)
}

// GetTransactionReceipt returns the receipt for the given tx.
func (ib *indexBackend) GetTransactionReceipt(txHash ethcommon.Hash) (map[string]interface{}, error) {
	dbReceipt, err := ib.storage.GetTransactionReceipt(txHash.String())
	if err != nil {
		return nil, err
	}

	ethLogs := []*ethtypes.Log{}
	for _, dbLog := range dbReceipt.Logs {
		topics := []ethcommon.Hash{}
		for _, dbTopic := range dbLog.Topics {
			tp := ethcommon.HexToHash(dbTopic)
			topics = append(topics, tp)
		}

		data, _ := hex.DecodeString(dbLog.Data)
		log := &ethtypes.Log{
			Address:     ethcommon.HexToAddress(dbLog.Address),
			Topics:      topics,
			Data:        data,
			BlockNumber: dbLog.Round,
			TxHash:      ethcommon.HexToHash(dbLog.TxHash),
			TxIndex:     dbLog.TxIndex,
			BlockHash:   ethcommon.HexToHash(dbLog.BlockHash),
			Index:       dbLog.Index,
			Removed:     dbLog.Removed,
		}

		ethLogs = append(ethLogs, log)
	}

	receipt := map[string]interface{}{
		"status":            hexutil.Uint(dbReceipt.Status),
		"cumulativeGasUsed": hexutil.Uint64(dbReceipt.CumulativeGasUsed),
		"logsBloom":         ethtypes.BytesToBloom(ethtypes.LogsBloom(ethLogs)),
		"logs":              ethLogs,
		"transactionHash":   dbReceipt.TransactionHash,
		"gasUsed":           hexutil.Uint64(dbReceipt.GasUsed),
		"type":              hexutil.Uint64(dbReceipt.Type),
		"blockHash":         dbReceipt.BlockHash,
		"blockNumber":       hexutil.Uint64(dbReceipt.Round),
		"transactionIndex":  hexutil.Uint64(dbReceipt.TransactionIndex),
		"from":              nil,
		"to":                nil,
		"contractAddress":   nil,
	}
	if dbReceipt.FromAddr != "" {
		receipt["from"] = dbReceipt.FromAddr
	}
	if dbReceipt.ToAddr != "" {
		receipt["to"] = dbReceipt.ToAddr
	}
	if dbReceipt.ContractAddress != "" {
		receipt["contractAddress"] = dbReceipt.ContractAddress
	}
	return receipt, nil
}

// BlockNumber returns the latest block.
func (ib *indexBackend) BlockNumber() (uint64, error) {
	return ib.storage.GetLatestBlockNumber()
}

// GetLogs returns logs from db.
func (ib *indexBackend) GetLogs(startRound, endRound uint64) ([]*model.Log, error) {
	return ib.storage.GetLogs(startRound, endRound)
}

// Close closes postgresql backend.
func (ib *indexBackend) Close() {
	ib.logger.Info("Indexer backend closed!")
}

// newPsqlBackend creates a Backend.
func newIndexBackend(ctx context.Context, runtimeID common.Namespace, storage storage.Storage, sb filters.SubscribeBackend) (Backend, error) {
	b := &indexBackend{
		ctx:       ctx,
		runtimeID: runtimeID,
		logger:    logging.GetLogger("indexer"),
		storage:   storage,
		subscribe: sb,
	}

	b.logger.Info("New indexer backend")

	return b, nil
}

// NewIndexBackend returns a PsqlBackend.
func NewIndexBackend() BackendFactory {
	return newIndexBackend
}
