package indexer

import (
	"context"
	"errors"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/client"

	"github.com/starfishlabs/oasis-evm-web3-gateway/filters"
	"github.com/starfishlabs/oasis-evm-web3-gateway/storage"
)

const (
	storageRequestTimeout = 5 * time.Second
	storageRetryTimeout   = 1 * time.Second
	pruningCheckInterval  = 60 * time.Second
)

var (
	ErrGetBlockFailed        = errors.New("get block failed")
	ErrGetTransactionsFailed = errors.New("get transactions failed")
	ErrIndexedFailed         = errors.New("index block failed")
)

// Service is an indexer service.
type Service struct {
	service.BaseBackgroundService

	runtimeID     common.Namespace
	enablePruning bool
	pruningStep   uint64

	backend Backend
	client  client.RuntimeClient

	ctx       context.Context
	cancelCtx context.CancelFunc
}

// indexBlock indexes given block number.
func (s *Service) indexBlock(round uint64) error {
	blk, err := s.client.GetBlock(s.ctx, round)
	if err != nil {
		return ErrGetBlockFailed
	}

	txs, err := s.client.GetTransactionsWithResults(s.ctx, blk.Header.Round)
	if err != nil {
		return ErrGetTransactionsFailed
	}

	err = s.backend.Index(blk, txs)
	if err != nil {
		return ErrIndexedFailed
	}

	return nil
}

// getRoundLatest returns the latest round.
func (s *Service) getRoundLatest() (uint64, error) {
	blk, err := s.client.GetBlock(s.ctx, client.RoundLatest)
	if err != nil {
		return 0, err
	}

	return blk.Header.Round, nil
}

// pruningWorker handles data pruning.
func (s *Service) pruningWorker() {
	s.Logger.Debug("starting periodic pruning worker")

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(pruningCheckInterval):
			lastIndexed, err := s.backend.QueryLastIndexedRound()
			if err != nil {
				s.Logger.Error("failed to query last indexed round",
					"err", err,
				)
				continue
			}

			if lastIndexed > s.pruningStep {
				round := lastIndexed - s.pruningStep
				if err := s.backend.Prune(round); err != nil {
					s.Logger.Error("failed to prune round",
						"err", err,
						"round", round,
					)
				}
			}
		}
	}
}

// indexingWorker is a worker for indexing.
func (s *Service) indexingWorker() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Query latest round available at the node.
		latest, err := s.getRoundLatest()
		if err != nil {
			time.Sleep(storageRequestTimeout)
			s.Logger.Info("failed to query latest round",
				"err", err,
			)
			continue
		}

		var startAt uint64
		// Get last indexed round.
		lastIndexed, err := s.backend.QueryLastIndexedRound()
		switch {
		case errors.Is(err, storage.ErrNoRoundsIndexed):
			// No rounds indexed, start at 0.
			startAt = 0
		case err != nil:
			s.Logger.Error("failed to query last indexed round",
				"err", err,
			)
			continue
		default:
			if latest < lastIndexed {
				panic("This is a new chain, please clear the db first!")
			}
			// Latest round already indexed.
			if latest == lastIndexed {
				time.Sleep(storageRetryTimeout)
				continue
			}
			startAt = lastIndexed + 1
		}

		// Get last retained round on the node.
		lastRetainedBlock, err := s.client.GetLastRetainedBlock(s.ctx)
		if err != nil {
			time.Sleep(storageRequestTimeout)
			s.Logger.Error("failed to retrieve last retained round",
				"err", err,
			)
			continue
		}
		// Adjust startAt round in case node pruned missing rounds.
		if lastRetainedBlock.Header.Round > startAt {
			startAt = lastRetainedBlock.Header.Round
		}

		for round := startAt; round <= latest; round++ {
			select {
			case <-s.ctx.Done():
				return
			default:
			}

			// Try to index block.
			if err = s.indexBlock(round); err != nil {
				time.Sleep(storageRequestTimeout)
				s.Logger.Warn("failed to index block",
					"err", err,
					"round", round,
				)
				break
			}

			// Update last indexed round for correct resumption.
			if err = s.backend.UpdateLastIndexedRound(round); err != nil {
				s.Logger.Warn("failed to update last indexed round",
					"err", err,
					"round", round,
				)
			}
		}
	}
}

// Start starts service.
func (s *Service) Start() {
	go s.indexingWorker()

	if s.enablePruning {
		go s.pruningWorker()
	}
}

// Stop stops service.
func (s *Service) Stop() {
	s.cancelCtx()
}

// New creates a new indexer service.
func New(
	backendFactory BackendFactory,
	client client.RuntimeClient,
	runtimeID common.Namespace,
	storage storage.Storage,
	enablePruning bool,
	pruningStep uint64,
) (*Service, Backend, filters.SubscribeBackend, error) {
	subBackend, err := filters.NewSubscribeBackend(storage)
	if err != nil {
		return nil, nil, nil, err
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	backend, err := backendFactory(ctx, runtimeID, storage, subBackend)
	if err != nil {
		cancelCtx()
		return nil, nil, nil, err
	}

	s := &Service{
		BaseBackgroundService: *service.NewBaseBackgroundService("gateway/indexer"),
		runtimeID:             runtimeID,
		backend:               backend,
		client:                client,
		ctx:                   ctx,
		cancelCtx:             cancelCtx,
		enablePruning:         enablePruning,
		pruningStep:           pruningStep,
	}
	s.Logger = s.Logger.With("runtime_id", s.runtimeID.String())

	return s, backend, subBackend, nil
}
