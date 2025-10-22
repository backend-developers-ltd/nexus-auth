package auth

import (
	"crypto/ed25519"
	"log"
	"sync"
	"time"
)

// cacheEntry holds a cached public key with its expiration time
type cacheEntry struct {
	publicKey ed25519.PublicKey
	expiresAt time.Time
}

// PublicKeyCache provides a thread-safe cache for public keys
// It uses a simple map-based implementation with expiration times
// If duration is 0, caching is disabled
type PublicKeyCache struct {
	mu       sync.RWMutex
	entries  map[string]cacheEntry
	duration time.Duration
	stopChan chan struct{}
}

// NewPublicKeyCache creates a new cache with the specified duration
// It starts a background goroutine to clean expired entries periodically
// If duration is 0, caching is disabled and Get/Set become no-ops
func NewPublicKeyCache(duration time.Duration) *PublicKeyCache {
	c := &PublicKeyCache{
		entries:  make(map[string]cacheEntry),
		duration: duration,
		stopChan: make(chan struct{}),
	}

	// Start background cleanup goroutine only if caching is enabled
	if duration > 0 {
		// Clean every duration/2 or at least every minute
		cleanInterval := duration / 2
		if cleanInterval < time.Minute {
			cleanInterval = time.Minute
		}
		go c.cleanupLoop(cleanInterval)
	}

	return c
}

// Get retrieves a public key from cache if it exists and hasn't expired
// Returns the public key and true if found and valid, nil and false otherwise
// If caching is disabled (duration <= 0), always returns nil and false
func (c *PublicKeyCache) Get(hotkey string) (ed25519.PublicKey, bool) {
	if c.duration <= 0 {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[hotkey]
	if !exists {
		return nil, false
	}

	// Check if entry has expired
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.publicKey, true
}

// Set stores a public key in the cache with the configured expiration
// If caching is disabled (duration <= 0), this is a no-op
func (c *PublicKeyCache) Set(hotkey string, publicKey ed25519.PublicKey) {
	if c.duration <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[hotkey] = cacheEntry{
		publicKey: publicKey,
		expiresAt: time.Now().Add(c.duration),
	}
}

// Clear removes all entries from the cache
func (c *PublicKeyCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := len(c.entries)
	c.entries = make(map[string]cacheEntry)
	log.Printf("Cleared cache (%d entries removed)", count)
}

// CleanExpired removes all expired entries from the cache
// This helps prevent unbounded memory growth
func (c *PublicKeyCache) CleanExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	count := 0
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
			count++
		}
	}
	if count > 0 {
		log.Printf("Cleaned %d expired cache entries", count)
	}
}

// cleanupLoop runs in the background and periodically cleans expired entries
func (c *PublicKeyCache) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.CleanExpired()
		case <-c.stopChan:
			return
		}
	}
}

// Stop stops the background cleanup goroutine
func (c *PublicKeyCache) Stop() {
	close(c.stopChan)
	log.Printf("Stopped cache cleanup goroutine")
}
