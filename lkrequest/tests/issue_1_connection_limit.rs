//! Regression PoC for GitHub Issue #1.

use lkrequest::Client;

// ---------------------------------------------------------------------------
// Issue #1: max_connections counts physical connection lifetime
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_max_connections_counts_checked_out_h1_connection() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, watch};

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("local address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let (accepted_tx, mut accepted_rx) = mpsc::unbounded_channel();
    let (release_tx, release_rx) = watch::channel(false);

    let server_accepted = Arc::clone(&accepted);
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let connection_number = server_accepted.fetch_add(1, Ordering::SeqCst) + 1;
            accepted_tx.send(connection_number).expect("report accept");
            let mut release_rx = release_rx.clone();
            tokio::spawn(async move {
                let mut request = vec![0_u8; 4096];
                let _ = stream.read(&mut request).await.expect("read request");
                if !*release_rx.borrow() {
                    release_rx.changed().await.expect("release signal");
                }
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK",
                    )
                    .await
                    .expect("write response");
            });
        }
    });

    let session = Client::default()
        .session()
        .http1_only()
        .max_connections(1)
        .build();
    let url = format!("http://{address}/");

    let first_session = session.clone();
    let first_url = url.clone();
    let first = tokio::spawn(async move { first_session.get(&first_url).send().await });
    assert_eq!(accepted_rx.recv().await, Some(1));

    let second_session = session.clone();
    let second_url = url.clone();
    let second = tokio::spawn(async move { second_session.get(&second_url).send().await });

    assert!(
        tokio::time::timeout(Duration::from_millis(200), accepted_rx.recv())
            .await
            .is_err(),
        "a second physical connection was opened"
    );
    let second_error = tokio::time::timeout(Duration::from_secs(1), second)
        .await
        .expect("second request did not fail promptly")
        .expect("second task")
        .expect_err("a checked-out H1 connection must consume the only slot");
    assert!(
        second_error
            .to_string()
            .contains("session connection limit reached"),
        "unexpected error: {second_error}"
    );

    let stats = session.pool_stats();
    assert_eq!(stats.total, 1, "stats must include the checked-out H1");
    assert_eq!(stats.h1_connections, 0, "checked-out H1 is not idle");
    assert!(stats.at_capacity);

    release_tx.send(true).expect("release first response");
    first.await.expect("first task").expect("first request");
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_idle_h1_does_not_block_a_new_origin_at_capacity() {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    async fn spawn_server() -> (
        std::net::SocketAddr,
        oneshot::Receiver<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("local address");
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _ = accepted_tx.send(());
            let mut request = vec![0_u8; 4096];
            let _ = stream.read(&mut request).await.expect("read request");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK",
                )
                .await
                .expect("write response");
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        (address, accepted_rx, server)
    }

    let (first_address, first_accepted, first_server) = spawn_server().await;
    let (second_address, second_accepted, second_server) = spawn_server().await;
    let session = Client::default()
        .session()
        .http1_only()
        .max_connections(1)
        .build();

    session
        .get(&format!("http://{first_address}/"))
        .send()
        .await
        .expect("first origin request");
    first_accepted.await.expect("first accepted");
    assert_eq!(session.pool_stats().total, 1);

    session
        .get(&format!("http://{second_address}/"))
        .send()
        .await
        .expect("idle connection should be evicted for the new origin");
    second_accepted.await.expect("second accepted");

    let stats = session.pool_stats();
    assert_eq!(stats.total, 1);
    assert_eq!(stats.h1_connections, 1);
    assert!(stats.at_capacity);

    first_server.abort();
    second_server.abort();
}
