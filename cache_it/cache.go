package cacheit

import (
	"sync"
	"time"
)

type CacheItem struct {
	value      interface{}
	expiration int64
}

type Cache struct {
	items map[string]CacheItem
	mutex sync.RWMutex
}

// Constructor
func NewCache() *Cache {
	cache := &Cache{
		items: make(map[string]CacheItem),
	}
	go cache.cleanup()
	return cache
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	item, found := c.items[key]
	if !found || (item.expiration > 0 && item.expiration < time.Now().UnixNano()) {
		return nil, false
	}

	return item.value, true
}

func (c *Cache) Set(key string, value interface{}, expiration time.Duration) {
	var exp int64
	if expiration > 0 {
		exp = time.Now().Add(expiration).UnixNano()
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.items[key] = CacheItem{
		value:      value,
		expiration: exp,
	}
}

func (c *Cache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.items, key)
}

func (c *Cache) cleanup() {
	for {
		time.Sleep(time.Minute)
		now := time.Now().UnixNano()

		c.mutex.Lock()
		for key, item := range c.items {
			if item.expiration > 0 && item.expiration < now {
				delete(c.items, key)
			}
		}
		c.mutex.Unlock()
	}
}

func main() {
	cache := NewCache()
	cache.Set("key1", "value1", time.Minute)
	value, found := cache.Get("key1")
	if found {
		println(value.(string)) // Output: value1
	}
	time.Sleep(2 * time.Minute)
	value, found = cache.Get("key1")
	if !found {
		println("key1 not found") // Output: key1 not found
	}
}
