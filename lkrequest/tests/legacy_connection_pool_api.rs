#![allow(deprecated)]

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::client::conn::http1::SendRequest;
use lkrequest::connection_pool::{ConnectionKey, ConnectionPool, PoolStats, PooledConnection};

type H1Sender = SendRequest<Full<Bytes>>;
type DriverTask = tokio::task::JoinHandle<()>;
type SharedDriverTask = Arc<DriverTask>;

fn consume_legacy_connection(connection: PooledConnection) {
    match connection {
        PooledConnection::H2(_) => {}
        #[cfg(feature = "quic-h3")]
        PooledConnection::H3(_) => {}
        PooledConnection::H1 {
            sender: _,
            conn_task: _,
        } => {}
    }
}

fn consume_legacy_stats(stats: PoolStats) {
    let PoolStats {
        h3_connections,
        h2_connections,
        h1_connections,
        total,
        max_total,
        at_capacity,
    } = stats;
    let _ = (
        h3_connections,
        h2_connections,
        h1_connections,
        total,
        max_total,
        at_capacity,
    );
}

#[test]
fn legacy_connection_pool_api_still_compiles() {
    let _acquire: fn(&mut ConnectionPool, &ConnectionKey) -> Option<PooledConnection> =
        ConnectionPool::try_acquire;
    let _acquire_h1: fn(&mut ConnectionPool, &ConnectionKey) -> Option<PooledConnection> =
        ConnectionPool::try_acquire_h1_pooled;
    let _acquire_h2: fn(&mut ConnectionPool, &ConnectionKey) -> Option<PooledConnection> =
        ConnectionPool::try_acquire_h2_pooled;
    let _insert_h2: fn(&mut ConnectionPool, ConnectionKey, lkh2::H2Sender, DriverTask) =
        ConnectionPool::insert_h2;
    let _insert_h1: fn(&mut ConnectionPool, ConnectionKey, H1Sender, DriverTask) =
        ConnectionPool::insert_h1;
    let _return_h1: fn(&mut ConnectionPool, ConnectionKey, H1Sender, SharedDriverTask) =
        ConnectionPool::return_h1;
    let _stats: fn(&ConnectionPool) -> PoolStats = ConnectionPool::stats;
    let _connection_shape: fn(PooledConnection) = consume_legacy_connection;
    let _stats_shape: fn(PoolStats) = consume_legacy_stats;

    let stats = ConnectionPool::new().stats();
    assert_eq!(stats.total, 0);
    assert!(!stats.at_capacity);
}

#[cfg(feature = "quic-h3")]
#[test]
fn legacy_h3_pool_api_still_compiles() {
    type H3DriverTask = Arc<tokio::task::JoinHandle<Result<(), lkh3::H3Error>>>;

    let _acquire_h3: fn(&mut ConnectionPool, &ConnectionKey) -> Option<PooledConnection> =
        ConnectionPool::try_acquire_h3_pooled;
    let _insert_h3: fn(&mut ConnectionPool, ConnectionKey, lkh3::H3Sender, H3DriverTask) =
        ConnectionPool::insert_h3;

    let stats = ConnectionPool::new().stats();
    assert_eq!(stats.h3_connections, 0);
}
