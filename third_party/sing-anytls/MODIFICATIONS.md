# Changes from upstream sing-anytls v0.0.11

- `session`: the client version string is no longer sent in settings (`util.Verison` is empty).
- `Service.UpdateUsers`: the user table is swapped atomically, so users can be changed while connections are being accepted.
- `session.Stream`: the close error is stored atomically. Closing a stream from another goroutine (the node does this to cut off a user) raced with `Read`/`Write`.
- `session.Session`: at most `MaxStreams` (1024) open streams per session; a client past it gets an alert and the session ends.
- `Service`: a new stream must name its destination within 30 s, and a stream that fails to is closed instead of left open.
