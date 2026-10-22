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

pub fn client_ip(app: &App, headers: &HeaderMap, peer: SocketAddr) -> String {
    if app.trust_proxy {
        if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = v.split(',').next() {
                let ip = first.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
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
        return (StatusCode::UNAUTHORIZED, "bad token").into_response();
    };
    let ip = client_ip(&app, &headers, peer);
    ws.max_message_size(4 << 20).on_upgrade(move |socket| serve(app, node.id, ip, socket))
}

async fn serve(app: Arc<App>, node_id: i64, ip: String, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();

    let hello = match tokio::time::timeout(HELLO_TIMEOUT, stream.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => match serde_json::from_str::<Value>(&text) {
            Ok(v) if v["type"] == "hello" => serde_json::from_value::<Hello>(v).unwrap_or_default(),
            _ => return,
        },
        _ => return,
    };
    eprintln!("node {node_id} connected from {ip} (keel-node {}, config rev {})", hello.node_version, hello.config_rev);

    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let conn_id = {
        let mut live = app.live();
        live.next_conn += 1;
        let id = live.next_conn;
        let l = live.nodes.entry(node_id).or_default();
        if let Some(old) = l.conn.replace(Conn { id, tx: tx.clone() }) {
            let _ = old.tx.send(Message::Close(None));
        }
        l.connected_at = now();
        l.last_seen = now();
        id
    };
    app.on_hello(node_id, hello, &ip);

    let writer = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let close = matches!(msg, Message::Close(_));
            if sink.send(msg).await.is_err() || close {
                break;
            }
        }
        let _ = sink.close().await;
    });

    app.sync();

    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await;
    let mut last = now();
    loop {
        tokio::select! {
            msg = stream.next() => {
                let Some(Ok(msg)) = msg else { break };
                last = now();
                match msg {
                    Message::Text(text) => {
                        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
                        match v["type"].as_str() {
                            Some("report") => {
                                if let Ok(r) = serde_json::from_value::<Report>(v) {
                                    app.on_report(node_id, r);
                                }
                            }
                            Some("applied") => app.on_applied(node_id, &v),
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
                if tx.send(Message::Text(r#"{"type":"ping"}"#.into())).is_err() {
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
    let _ = tx.send(Message::Close(None));
    drop(tx);
    let _ = writer.await;
    eprintln!("node {node_id} disconnected");
}
