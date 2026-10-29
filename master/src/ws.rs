//! The node control channel: keel-node dials wss://<master>/api/node/ws with
//! its token and keeps the connection open (docs/node-protocol.md).

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::app::App;
use crate::db;
use crate::live::{Conn, Hello, Report};
use crate::period::now;

const HELLO_TIMEOUT: Duration = Duration::from_secs(15);
const PING_INTERVAL: Duration = Duration::from_secs(20);
/// A node that sent nothing for this long is treated as gone.
const IDLE_LIMIT: i64 = 60;
/// Messages queued for one node; a full queue disconnects it.
const QUEUE: usize = 16;
/// A node must take a message within this, or it is disconnected.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The client's address. Behind -no-tls it is the last X-Forwarded-For
/// entry, the one the reverse proxy appended; earlier entries come from the
/// client and can say anything.
pub fn client_ip(app: &App, headers: &HeaderMap, peer: SocketAddr) -> String {
    if app.trust_proxy {
        let last = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .last()
            .and_then(|ip| ip.trim().parse::<std::net::IpAddr>().ok());
        if let Some(ip) = last {
            return ip.to_canonical().to_string();
        }
    }
    peer.ip().to_canonical().to_string()
}

pub async fn handler(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .trim()
        .to_string();
    let node = if token.is_empty() { None } else { db::node_by_token(&app.db(), &token).ok().flatten() };
    let Some(node) = node else {
        tokio::time::sleep(Duration::from_secs(1)).await;
        // Close it: a rejected node would otherwise keep the socket alive.
        return (StatusCode::UNAUTHORIZED, [(axum::http::header::CONNECTION, "close")], "bad token").into_response();
    };
    let ip = client_ip(&app, &headers, peer);
    let token = node.token.clone();
    ws.max_message_size(4 << 20).max_frame_size(4 << 20).on_upgrade(move |socket| serve(app, node.id, token, ip, socket))
}

async fn serve(app: Arc<App>, node_id: i64, token: String, ip: String, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();

    let hello = match tokio::time::timeout(HELLO_TIMEOUT, stream.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => match serde_json::from_str::<Value>(&text) {
            Ok(v) if v["type"] == "hello" => serde_json::from_value::<Hello>(v).unwrap_or_default(),
            _ => return,
        },
        _ => return,
    };
    // Node-supplied text is quoted, so it cannot forge log lines.
    let version: String = hello.node_version.chars().take(64).collect();
    eprintln!("node {node_id} connected from {ip} (keel-node {version:?}, config rev {})", hello.config_rev);

    let (tx, mut rx) = mpsc::channel::<Message>(QUEUE);
    let stop = Arc::new(tokio::sync::Notify::new());
    let conn_id = {
        // The token was checked before the upgrade; check it again, holding
        // the database lock, so a rotation or deletion that happened since
        // (or happens now) cannot miss this connection.
        let db = app.db();
        let current = db::node_by_token(&db, &token).ok().flatten().is_some_and(|n| n.id == node_id);
        if !current {
            return;
        }
        let mut live = app.live();
        live.next_conn += 1;
        let id = live.next_conn;
        let l = live.nodes.entry(node_id).or_default();
        if let Some(old) = l.conn.replace(Conn { id, tx: tx.clone(), stop: stop.clone() }) {
            old.stop.notify_one();
        }
        l.connected_at = now();
        l.last_seen = now();
        id
    };
    // Cloudflare is only called when the node's address actually changed:
    // reconnecting in a loop must not make the master hammer the API.
    if app.on_hello(node_id, hello, &ip) {
        crate::dns::spawn_sync(app.clone());
    }

    let mut writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let close = matches!(msg, Message::Close(_));
            if !matches!(tokio::time::timeout(WRITE_TIMEOUT, sink.send(msg)).await, Ok(Ok(()))) || close {
                break;
            }
        }
        let _ = tokio::time::timeout(WRITE_TIMEOUT, sink.close()).await;
    });

    app.sync_node(node_id);

    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await;
    let mut last = now();
    loop {
        tokio::select! {
            _ = stop.notified() => break,
            msg = stream.next() => {
                let Some(Ok(msg)) = msg else { break };
                last = now();
                match msg {
                    Message::Text(text) => {
                        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
                        match v["type"].as_str() {
                            Some("report") => {
                                // Only the node's current connection may report.
                                let current = app.live().nodes.get(&node_id).and_then(|l| l.conn.as_ref()).is_some_and(|c| c.id == conn_id);
                                if !current {
                                    break;
                                }
                                // A malformed system/probe/health section must not
                                // drop the usage counters in the same report.
                                let parsed = serde_json::from_value::<Report>(v.clone()).or_else(|_| {
                                    let mut v = v;
                                    if let Some(o) = v.as_object_mut() {
                                        for k in ["system", "probes", "outbounds", "certs"] {
                                            o.remove(k);
                                        }
                                    }
                                    serde_json::from_value::<Report>(v)
                                });
                                if let Ok(r) = parsed {
                                    app.on_report(node_id, r);
                                }
                            }
                            Some("applied") => app.on_applied(node_id, &v),
                            Some("acme_dns") => {
                                let app = app.clone();
                                tokio::spawn(async move {
                                    let res = crate::dns::acme_challenge(
                                        &app,
                                        node_id,
                                        v["op"].as_str().unwrap_or(""),
                                        v["domain"].as_str().unwrap_or(""),
                                        v["value"].as_str().unwrap_or(""),
                                    )
                                    .await;
                                    let reply = serde_json::json!({"type": "acme_dns_done", "id": v["id"].as_i64().unwrap_or(0), "error": res.err().unwrap_or_default()});
                                    if let Some(c) = app.live().nodes.get(&node_id).and_then(|l| l.conn.as_ref()) {
                                        c.send(Message::Text(reply.to_string().into()));
                                    }
                                });
                            }
                            _ => {}
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            _ = ping.tick() => {
                if now() - last > IDLE_LIMIT {
                    break;
                }
                if tx.try_send(Message::Text(r#"{"type":"ping"}"#.into())).is_err() {
                    break;
                }
            }
        }
    }

    {
        let mut live = app.live();
        if let Some(l) = live.nodes.get_mut(&node_id) {
            if l.conn.as_ref().is_some_and(|c| c.id == conn_id) {
                l.conn = None;
                l.conns.clear();
                l.outbounds.clear();
            }
        }
    }
    let _ = tx.try_send(Message::Close(None));
    drop(tx);
    // A writer stuck on a node that does not read is not waited for.
    if tokio::time::timeout(WRITE_TIMEOUT, &mut writer).await.is_err() {
        writer.abort();
    }
    eprintln!("node {node_id} disconnected");
}
