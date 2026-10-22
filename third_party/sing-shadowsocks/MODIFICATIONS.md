# Changes from upstream sing-shadowsocks v0.2.8

- `shadowaead_2022.MultiService`: the user tables are swapped atomically by `UpdateUsers`. Upstream assigns the maps without synchronization while TCP and UDP handling read them, a data race whenever users change on a running server.
