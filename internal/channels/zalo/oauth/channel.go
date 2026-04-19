package zalooauth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/nextlevelbuilder/goclaw/internal/bus"
	"github.com/nextlevelbuilder/goclaw/internal/channels"
	"github.com/nextlevelbuilder/goclaw/internal/config"
	"github.com/nextlevelbuilder/goclaw/internal/store"
)

// ErrSendNotImplemented is returned by Send until phase 03 wires real outbound.
var ErrSendNotImplemented = errors.New("zalo_oauth: send not implemented (wired in phase 03)")

const defaultClientTimeout = 15 * time.Second

// Channel is the phase-01 stub. Phase 02 wires lazy refresh + safety ticker;
// phase 03 wires Send; phase 04 wires inbound polling.
type Channel struct {
	*channels.BaseChannel

	client  *Client
	creds   *ChannelCreds
	ciStore store.ChannelInstanceStore
	cfg     config.ZaloOAuthConfig
}

// New constructs a stub channel. Lifecycle methods are intentionally minimal
// in phase 01.
func New(name string, cfg config.ZaloOAuthConfig, creds *ChannelCreds,
	ciStore store.ChannelInstanceStore, msgBus *bus.MessageBus, _ store.PairingStore) (*Channel, error) {

	if creds == nil {
		return nil, errors.New("zalo_oauth: nil creds")
	}
	if creds.AppID == "" || creds.SecretKey == "" {
		return nil, errors.New("zalo_oauth: app_id and secret_key are required")
	}

	return &Channel{
		BaseChannel: channels.NewBaseChannel(name, msgBus, []string(cfg.AllowFrom)),
		client:      NewClient(defaultClientTimeout),
		creds:       creds,
		ciStore:     ciStore,
		cfg:         cfg,
	}, nil
}

// Type returns the channel type identifier.
func (c *Channel) Type() string { return channels.TypeZaloOAuth }

// Start brings the channel up. Phase 01: just mark ready.
// Phase 02 will start the safety ticker. Phase 04 will start the poll loop.
func (c *Channel) Start(_ context.Context) error {
	c.SetRunning(true)
	if c.creds.OAID != "" {
		slog.Info("zalo_oauth.started", "state", "connected", "oa_id", c.creds.OAID, "name", c.Name())
		c.MarkHealthy("connected")
	} else {
		slog.Info("zalo_oauth.started", "state", "unauthorized", "name", c.Name())
		c.MarkDegraded("awaiting consent", "no oa_id yet — paste consent code to authorize",
			channels.ChannelFailureKindAuth, true)
	}
	return nil
}

// Stop marks the channel stopped. Phase 02/04 will close goroutine stop signals here.
func (c *Channel) Stop(_ context.Context) error {
	c.SetRunning(false)
	slog.Info("zalo_oauth.stopped", "name", c.Name())
	return nil
}

// Send is wired in phase 03.
func (c *Channel) Send(_ context.Context, _ bus.OutboundMessage) error {
	return ErrSendNotImplemented
}
