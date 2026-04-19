package zalooauth

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nextlevelbuilder/goclaw/internal/bus"
	"github.com/nextlevelbuilder/goclaw/internal/channels"
	"github.com/nextlevelbuilder/goclaw/internal/config"
	"github.com/nextlevelbuilder/goclaw/internal/store"
)

// ErrSendNotImplemented is returned by Send until phase 03 wires real outbound.
var ErrSendNotImplemented = errors.New("zalo_oauth: send not implemented (wired in phase 03)")

const (
	defaultClientTimeout        = 15 * time.Second
	defaultSafetyTickerInterval = 30 * time.Minute
)

// Channel is the phase-02 form. Phase 03 wires Send; phase 04 wires polling.
type Channel struct {
	*channels.BaseChannel

	client  *Client
	creds   *ChannelCreds
	ciStore store.ChannelInstanceStore
	cfg     config.ZaloOAuthConfig

	// instanceID is injected by InstanceLoader via SetInstanceID after construction
	// (ChannelFactory signature doesn't expose it).
	instanceID uuid.UUID

	tokens *tokenSource

	// safetyTickerInterval is exposed for tests; production uses defaultSafetyTickerInterval
	// or cfg.SafetyTickerMinutes.
	safetyTickerInterval time.Duration

	stopOnce sync.Once
	stopCh   chan struct{}
	tickerWG sync.WaitGroup
}

// New constructs the channel. InstanceLoader calls SetInstanceID after this.
func New(name string, cfg config.ZaloOAuthConfig, creds *ChannelCreds,
	ciStore store.ChannelInstanceStore, msgBus *bus.MessageBus, _ store.PairingStore) (*Channel, error) {

	if creds == nil {
		return nil, errors.New("zalo_oauth: nil creds")
	}
	if creds.AppID == "" || creds.SecretKey == "" {
		return nil, errors.New("zalo_oauth: app_id and secret_key are required")
	}

	c := &Channel{
		BaseChannel:          channels.NewBaseChannel(name, msgBus, []string(cfg.AllowFrom)),
		client:               NewClient(defaultClientTimeout),
		creds:                creds,
		ciStore:              ciStore,
		cfg:                  cfg,
		safetyTickerInterval: tickerInterval(cfg.SafetyTickerMinutes),
		stopCh:               make(chan struct{}),
	}
	c.tokens = &tokenSource{
		client: c.client,
		creds:  c.creds,
		store:  c.ciStore,
	}
	return c, nil
}

// SetInstanceID is called by InstanceLoader after construction. The instance
// ID is needed by the token-refresh path to write back rotated credentials.
func (c *Channel) SetInstanceID(id uuid.UUID) {
	c.instanceID = id
	c.tokens.instanceID = id
}

// Type returns the channel type identifier.
func (c *Channel) Type() string { return channels.TypeZaloOAuth }

// Start brings the channel up and spawns the safety-ticker goroutine.
// Phase 04 will start the polling loop here.
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

	c.tickerWG.Add(1)
	go c.runSafetyTicker()
	return nil
}

// Stop signals the ticker to exit and waits for it. Idempotent.
func (c *Channel) Stop(_ context.Context) error {
	c.stopOnce.Do(func() { close(c.stopCh) })
	c.tickerWG.Wait()
	c.SetRunning(false)
	slog.Info("zalo_oauth.stopped", "name", c.Name())
	return nil
}

// Send is wired in phase 03.
func (c *Channel) Send(_ context.Context, _ bus.OutboundMessage) error {
	return ErrSendNotImplemented
}

// runSafetyTicker calls Access() periodically so idle channels don't let
// the refresh-token rotation window lapse silently. Skips work if the
// channel is already in auth-failed state to avoid log spam.
func (c *Channel) runSafetyTicker() {
	defer c.tickerWG.Done()

	t := time.NewTicker(c.safetyTickerInterval)
	defer t.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-t.C:
			if c.skipTickIfAuthFailed() {
				continue
			}
			// Access() does its own under-mutex check for refreshMargin —
			// we deliberately don't pre-read creds.ExpiresAt here to avoid
			// racing with concurrent refresh writes from Send (phase 03+).
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if _, err := c.tokens.Access(ctx); err != nil && !errors.Is(err, ErrNotAuthorized) {
				c.markAuthFailedIfNeeded(err)
				slog.Warn("zalo_oauth.safety_tick_refresh_failed", "instance_id", c.instanceID, "error", err)
			}
			cancel()
		}
	}
}

// skipTickIfAuthFailed avoids re-attempting refresh once the channel is in
// permanent auth-failed state (operator must re-auth).
func (c *Channel) skipTickIfAuthFailed() bool {
	snap := c.HealthSnapshot()
	return snap.State == channels.ChannelHealthStateFailed && snap.FailureKind == channels.ChannelFailureKindAuth
}

// markAuthFailedIfNeeded transitions health to Failed/Auth on ErrAuthExpired.
func (c *Channel) markAuthFailedIfNeeded(err error) {
	if errors.Is(err, ErrAuthExpired) {
		c.MarkFailed("Re-auth required",
			"Zalo refresh token expired or invalid; operator must re-paste consent code",
			channels.ChannelFailureKindAuth,
			false, // not retryable by automation
		)
	}
}

// tickerInterval clamps the ticker to a sane range.
func tickerInterval(cfgMinutes int) time.Duration {
	switch {
	case cfgMinutes < 5:
		return defaultSafetyTickerInterval
	case cfgMinutes > 120:
		return 120 * time.Minute
	default:
		return time.Duration(cfgMinutes) * time.Minute
	}
}
