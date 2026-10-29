# Changes from upstream sing-shadowsocks v0.2.8

- `shadowaead_2022.MultiService`: the user tables are swapped atomically by `UpdateUsers`. Upstream assigns the maps without synchronization while TCP and UDP handling read them, a data race whenever users change on a running server.
- `shadowaead_2022.MultiService.NewConnection0`: a TCP request's salt enters the replay filter only after its first chunk authenticated. Upstream recorded the salt of every connection, so anyone could grow the filter (and its periodic cleanup under a lock) without knowing a key. Replayed requests are still refused.
