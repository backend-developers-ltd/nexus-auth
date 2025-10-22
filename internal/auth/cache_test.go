package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestPublicKeyCache_GetSet(t *testing.T) {
	cache := NewPublicKeyCache(5 * time.Minute)

	// Generate a test public key
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	hotkey := "test-hotkey"

	// Test cache miss
	_, found := cache.Get(hotkey)
	if found {
		t.Error("Expected cache miss, but got hit")
	}

	// Set the key
	cache.Set(hotkey, pubKey)

	// Test cache hit
	cachedKey, found := cache.Get(hotkey)
	if !found {
		t.Error("Expected cache hit, but got miss")
	}

	// Verify the cached key matches
	if len(cachedKey) != len(pubKey) {
		t.Error("Cached key length doesn't match")
	}
	for i := range cachedKey {
		if cachedKey[i] != pubKey[i] {
			t.Error("Cached key doesn't match original key")
			break
		}
	}
}

func TestPublicKeyCache_Expiration(t *testing.T) {
	// Create cache with very short duration
	cache := NewPublicKeyCache(100 * time.Millisecond)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	hotkey := "test-hotkey"

	// Set the key
	cache.Set(hotkey, pubKey)

	// Should be cached immediately
	_, found := cache.Get(hotkey)
	if !found {
		t.Error("Expected cache hit immediately after set")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should be expired now
	_, found = cache.Get(hotkey)
	if found {
		t.Error("Expected cache miss after expiration")
	}
}

func TestPublicKeyCache_Clear(t *testing.T) {
	cache := NewPublicKeyCache(5 * time.Minute)

	pubKey1, _, _ := ed25519.GenerateKey(rand.Reader)
	pubKey2, _, _ := ed25519.GenerateKey(rand.Reader)

	cache.Set("hotkey1", pubKey1)
	cache.Set("hotkey2", pubKey2)

	// Both should be cached
	_, found := cache.Get("hotkey1")
	if !found {
		t.Error("Expected cache hit for hotkey1")
	}
	_, found = cache.Get("hotkey2")
	if !found {
		t.Error("Expected cache hit for hotkey2")
	}

	// Clear cache
	cache.Clear()

	// Both should be gone
	_, found = cache.Get("hotkey1")
	if found {
		t.Error("Expected cache miss for hotkey1 after clear")
	}
	_, found = cache.Get("hotkey2")
	if found {
		t.Error("Expected cache miss for hotkey2 after clear")
	}
}

func TestPublicKeyCache_CleanExpired(t *testing.T) {
	cache := NewPublicKeyCache(100 * time.Millisecond)

	pubKey1, _, _ := ed25519.GenerateKey(rand.Reader)
	pubKey2, _, _ := ed25519.GenerateKey(rand.Reader)

	cache.Set("hotkey1", pubKey1)

	// Wait for first key to expire
	time.Sleep(150 * time.Millisecond)

	// Set second key (not expired)
	cache.Set("hotkey2", pubKey2)

	// Clean expired entries
	cache.CleanExpired()

	// First key should be gone
	_, found := cache.Get("hotkey1")
	if found {
		t.Error("Expected cache miss for expired hotkey1 after clean")
	}

	// Second key should still be there
	_, found = cache.Get("hotkey2")
	if !found {
		t.Error("Expected cache hit for non-expired hotkey2 after clean")
	}
}

func TestPublicKeyCache_MultipleKeys(t *testing.T) {
	cache := NewPublicKeyCache(5 * time.Minute)

	keys := make(map[string]ed25519.PublicKey)
	for i := 0; i < 10; i++ {
		pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
		hotkey := string(rune('A' + i))
		keys[hotkey] = pubKey
		cache.Set(hotkey, pubKey)
	}

	// Verify all keys are cached correctly
	for hotkey, expectedKey := range keys {
		cachedKey, found := cache.Get(hotkey)
		if !found {
			t.Errorf("Expected cache hit for hotkey %s", hotkey)
			continue
		}
		if len(cachedKey) != len(expectedKey) {
			t.Errorf("Cached key length doesn't match for hotkey %s", hotkey)
			continue
		}
		for i := range cachedKey {
			if cachedKey[i] != expectedKey[i] {
				t.Errorf("Cached key doesn't match for hotkey %s", hotkey)
				break
			}
		}
	}
}

func TestPublicKeyCache_ZeroDuration(t *testing.T) {
	// Cache with zero duration should expire immediately
	cache := NewPublicKeyCache(0)
	defer cache.Stop()

	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	hotkey := "test-hotkey"

	cache.Set(hotkey, pubKey)

	// Should be expired immediately
	_, found := cache.Get(hotkey)
	if found {
		t.Error("Expected cache miss with zero duration")
	}
}

func TestPublicKeyCache_AutoCleanup(t *testing.T) {
	// Create cache with 200ms duration (cleanup every 100ms or 1min, whichever is larger)
	// Since 100ms < 1min, cleanup will run every 1min by default
	// For testing, we'll use a shorter duration and verify manual cleanup works
	cache := NewPublicKeyCache(200 * time.Millisecond)
	defer cache.Stop()

	pubKey1, _, _ := ed25519.GenerateKey(rand.Reader)
	pubKey2, _, _ := ed25519.GenerateKey(rand.Reader)

	cache.Set("hotkey1", pubKey1)

	// Wait for first key to expire
	time.Sleep(250 * time.Millisecond)

	// Add second key (not expired)
	cache.Set("hotkey2", pubKey2)

	// Manually trigger cleanup to verify it works
	cache.CleanExpired()

	// Verify cleanup removed expired entry
	_, found := cache.Get("hotkey1")
	if found {
		t.Error("Expected hotkey1 to be cleaned up")
	}

	// Verify non-expired entry still exists
	_, found = cache.Get("hotkey2")
	if !found {
		t.Error("Expected hotkey2 to still exist")
	}
}

func TestPublicKeyCache_Stop(t *testing.T) {
	cache := NewPublicKeyCache(5 * time.Minute)

	// Stop should not panic
	cache.Stop()

	// Cache should still work after stop
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	cache.Set("test", pubKey)

	cachedKey, found := cache.Get("test")
	if !found {
		t.Error("Expected cache to work after Stop")
	}
	if len(cachedKey) != len(pubKey) {
		t.Error("Cached key doesn't match after Stop")
	}
}
