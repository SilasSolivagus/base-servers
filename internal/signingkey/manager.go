package signingkey

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// DefaultRetireWindow:退休窗口 ≥ 最大委托 TTL(24h)+ 验证方缓存 + 时钟偏移。
const DefaultRetireWindow = 25 * time.Hour

// DefaultCacheTTL:Keyset 内存缓存有效期;跨副本最终一致的时间上界。
const DefaultCacheTTL = 30 * time.Second

// Keyset 是当前 live 键集合;Active 用于签名,All 用于 Verify/JWKS。
type Keyset struct {
	Active Key
	All    []Key
}

type Options struct {
	RetireWindow time.Duration
	CacheTTL     time.Duration
	Now          func() time.Time
}

type Manager struct {
	store  *Store
	cipher *Cipher
	opt    Options

	mu       sync.RWMutex
	cached   Keyset
	loadedAt time.Time
}

func NewManager(store *Store, cipher *Cipher) *Manager {
	return NewManagerWithOptions(store, cipher, Options{})
}

func NewManagerWithOptions(store *Store, cipher *Cipher, o Options) *Manager {
	if o.RetireWindow == 0 {
		o.RetireWindow = DefaultRetireWindow
	}
	if o.CacheTTL == 0 {
		o.CacheTTL = DefaultCacheTTL
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Manager{store: store, cipher: cipher, opt: o}
}

// EnsureActive 保证库中存在一把可解密的 active 键,并加载 keyset。
// 首启无 active:生成→加密→插入;竞态失败(23505)说明别的副本已建 → 回读。
// 错 KEK:refresh 解密失败 → 返回错误,绝不新铸。
func (m *Manager) EnsureActive(ctx context.Context) error {
	if _, err := m.store.GetActive(ctx); err != nil {
		if !errors.Is(err, ErrNoActive) {
			return err
		}
		if err := m.mint(ctx); err != nil {
			return err
		}
	}
	return m.refresh(ctx)
}

func (m *Manager) mint(ctx context.Context) error {
	k, err := GenerateKey()
	if err != nil {
		return err
	}
	der, err := MarshalPriv(k.Priv)
	if err != nil {
		return err
	}
	enc, err := m.cipher.Seal(k.Kid, der)
	if err != nil {
		return err
	}
	err = m.store.Insert(ctx, KeyRow{Kid: k.Kid, Alg: "ES256", State: "active", PrivateEnc: enc})
	if isUniqueViolation(err) {
		return nil // 另一副本抢先,回读即可
	}
	return err
}

func (m *Manager) refresh(ctx context.Context) error {
	rows, err := m.store.ListLive(ctx)
	if err != nil {
		return err
	}
	var ks Keyset
	for _, r := range rows {
		der, err := m.cipher.Open(r.Kid, r.PrivateEnc)
		if err != nil {
			return fmt.Errorf("decrypt signing key %s (wrong BS_SIGNING_KEK?): %w", r.Kid, err)
		}
		priv, err := ParsePriv(der)
		if err != nil {
			return fmt.Errorf("parse signing key %s: %w", r.Kid, err)
		}
		key := Key{Kid: r.Kid, Priv: priv}
		ks.All = append(ks.All, key)
		if r.State == "active" {
			ks.Active = key
		}
	}
	m.mu.Lock()
	m.cached = ks
	m.loadedAt = m.opt.Now()
	m.mu.Unlock()
	return nil
}

// Keyset 返回缓存 keyset;超过 CacheTTL 则从库刷新(用内部 ctx)。
// 刷新失败保留旧 keyset —— 启动时的 EnsureActive 已保证首次加载成功。
func (m *Manager) Keyset() Keyset {
	m.mu.RLock()
	age := m.opt.Now().Sub(m.loadedAt)
	ks := m.cached
	m.mu.RUnlock()
	if age <= m.opt.CacheTTL {
		return ks
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = m.refresh(ctx)
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cached
}

// Rotate 生成新 active 键、把旧 active 降级 retiring(retire_after=now+window),
// 清理已过期的 retiring 键,并刷新缓存。
func (m *Manager) Rotate(ctx context.Context) (Key, error) {
	k, err := GenerateKey()
	if err != nil {
		return Key{}, err
	}
	der, err := MarshalPriv(k.Priv)
	if err != nil {
		return Key{}, err
	}
	enc, err := m.cipher.Seal(k.Kid, der)
	if err != nil {
		return Key{}, err
	}
	retireAfter := m.opt.Now().Add(m.opt.RetireWindow)
	if err := m.store.Rotate(ctx, KeyRow{Kid: k.Kid, Alg: "ES256", State: "active", PrivateEnc: enc}, retireAfter); err != nil {
		return Key{}, err
	}
	if _, err := m.store.RetireExpired(ctx); err != nil {
		return Key{}, err
	}
	if err := m.refresh(ctx); err != nil {
		return Key{}, err
	}
	return *k, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
