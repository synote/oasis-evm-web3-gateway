package filters

import (
	"context"

	ethereum "github.com/ethereum/go-ethereum"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	ethfilters "github.com/ethereum/go-ethereum/eth/filters"
	ethrpc "github.com/ethereum/go-ethereum/rpc"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-sdk/client-sdk/go/client"

	eventFilters "github.com/starfishlabs/oasis-evm-web3-gateway/filters"
	"github.com/starfishlabs/oasis-evm-web3-gateway/indexer"
)

// PublicAPI is the eth_ prefixed set of APIs in the Web3 JSON-RPC spec.
type PublicFilterAPI struct {
	ctx     context.Context
	client  client.RuntimeClient
	backend indexer.Backend
	Logger  *logging.Logger
	es      *eventFilters.EventSystem
}

// NewPublicAPI creates an instance of the public ETH Web3 API with filter func.
func NewPublicAPI(
	ctx context.Context,
	client client.RuntimeClient,
	logger *logging.Logger,
	backend indexer.Backend,
	eventSystem *eventFilters.EventSystem,
) *PublicFilterAPI {
	return &PublicFilterAPI{
		ctx:     ctx,
		client:  client,
		Logger:  logger,
		backend: backend,
		es:      eventSystem,
	}
}

func (api *PublicFilterAPI) NewHeads(ctx context.Context) (*ethrpc.Subscription, error) {
	notifier, supported := ethrpc.NotifierFromContext(ctx)
	if !supported {
		return &ethrpc.Subscription{}, ethrpc.ErrNotificationsUnsupported
	}

	rpcSub := notifier.CreateSubscription()

	go func() {
		headers := make(chan *ethtypes.Header)
		headersSub := api.es.SubscribeNewHeads(headers)

		for {
			select {
			case h := <-headers:
				if err := notifier.Notify(rpcSub.ID, h); err != nil {
					api.Logger.Warn("some error happen when notify new headers,", "err", err)
				}
			case <-rpcSub.Err():
				// client send an unsubscribe request
				headersSub.Unsubscribe()
				return
			case <-notifier.Closed():
				// connection dropped
				headersSub.Unsubscribe()
				return
			}
		}
	}()

	return rpcSub, nil
}

func (api *PublicFilterAPI) Logs(ctx context.Context, crit ethfilters.FilterCriteria) (*ethrpc.Subscription, error) {
	notifier, supported := ethrpc.NotifierFromContext(ctx)
	if !supported {
		return &ethrpc.Subscription{}, ethrpc.ErrNotificationsUnsupported
	}

	rpcSub := notifier.CreateSubscription()
	matchedLogs := make(chan []*ethtypes.Log)

	logsSub, err := api.es.SubscribeLogs(ethereum.FilterQuery(crit), matchedLogs)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			select {
			case logs := <-matchedLogs:
				for _, log := range logs {
					if err := notifier.Notify(rpcSub.ID, log); err != nil {
						api.Logger.Warn("some error happen when notify logs,", "err", err)
					}
				}
			case <-rpcSub.Err():
				// client send an unsubscribe request
				logsSub.Unsubscribe()
				return
			case <-notifier.Closed():
				// connection dropped
				logsSub.Unsubscribe()
				return
			}
		}
	}()

	return rpcSub, nil
}
