//! Tier-0 connector regression: handshake fails cleanly when the peer closes immediately.

use lkrequest::TlsConnector;
use lktls::profile::presets;
use tokio::net::TcpListener;

#[tokio::test]
async fn connect_peer_closes_after_accept() {
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();

    let j = tokio::spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        addr_tx.send(addr).ok();
        if let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });

    let addr = addr_rx.await.expect("server addr");
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let connector = TlsConnector::new(presets::chrome_144());
    let res = connector.connect("127.0.0.1", addr.port(), tcp).await;
    assert!(
        res.is_err(),
        "expected handshake failure after peer close, got {res:?}"
    );
    let _ = j.await;
}
