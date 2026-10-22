# Changes from upstream sing-anytls v0.0.11

- `padding.DefaultPaddingScheme`: shorter scheme (`stop=3`, smaller first packets).
- `session`: the client version string is no longer sent in settings (`util.Verison` is empty).
- `Service.UpdateUsers`: the user table is swapped atomically, so users can be changed while connections are being accepted.
- `session.Stream`: the close error is stored atomically. Closing a stream from another goroutine (the node does this to cut off a user) raced with `Read`/`Write`.
