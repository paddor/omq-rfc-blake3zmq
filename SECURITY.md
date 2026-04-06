# Security

The RFC is currently a work-in-progress. It is based on novel AEAD crypto
composition. Even if the RFC passes a thorough security audit and eventually
reaches stable state, being a Ruby gem brings certain limitations.

## No memory protection

No `mlock()` is done to prevent key material from hitting swap,
and no memory is zeroed after use.

- Private keys live as regular Ruby `String` objects on the GC heap
- They get copied during GC compaction
- They persist in memory after the object is collected (until
  overwritten)
- They can end up in swap, core dumps, or process memory snapshots

## Ruby runtime attack surface

- **GC observability** — an attacker sharing the process could observe
  GC timing correlated with key operations
- **ObjectSpace** — `ObjectSpace.each_object(String)` can enumerate
  key material in the same process
- **No stack clearing** — local variables holding key fragments persist
  on the Ruby stack/heap
