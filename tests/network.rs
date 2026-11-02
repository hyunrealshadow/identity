//! Real HTTP transport behavior with local protocol peers.
use identity_application::openid_connect::remote::{
    DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteFetchError, fetch_document_after_url_validation,
};
use reqwest::{Client, redirect::Policy};
use std::time::Duration;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    spawn,
    time::{sleep, timeout},
};
use url::Url;
#[tokio::test]
async fn fetch_request_object_rejects_oversized_chunked_response_before_completion() {
    let request_uri = spawn_chunked_response_server(
        vec![vec![b'a'; 1024 * 1024], vec![b'b'; 1]],
        Duration::from_secs(6),
    )
    .await;
    let client = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let result = timeout(
        Duration::from_secs(2),
        fetch_document_after_url_validation(
            &client,
            &request_uri,
            DEFAULT_REMOTE_DOCUMENT_MAX_BYTES,
        ),
    )
    .await;

    let error = result
        .expect("oversized response should be rejected before server finishes")
        .unwrap_err();
    assert!(matches!(error, RemoteFetchError::TooLarge));
}
#[tokio::test]
async fn fetch_request_object_rejects_redirect_response() {
    let request_uri = spawn_redirect_response_server("http://127.0.0.1/final.jwt").await;
    let client = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let error = fetch_document_after_url_validation(
        &client,
        &request_uri,
        DEFAULT_REMOTE_DOCUMENT_MAX_BYTES,
    )
    .await
    .unwrap_err();

    assert!(matches!(error, RemoteFetchError::NotOk));
}
async fn spawn_chunked_response_server(chunks: Vec<Vec<u8>>, keep_open_for: Duration) -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n",
                )
                .await
                .unwrap();

        for chunk in chunks {
            stream
                .write_all(format!("{:X}\r\n", chunk.len()).as_bytes())
                .await
                .unwrap();
            stream.write_all(&chunk).await.unwrap();
            stream.write_all(b"\r\n").await.unwrap();
        }

        sleep(keep_open_for).await;
    });

    Url::parse(&format!("http://{address}/request.jwt")).unwrap()
}

async fn spawn_redirect_response_server(_location: &str) -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let location = format!("http://{address}/final.jwt");

    spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let response = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).await.unwrap();

        let (mut stream, _) = listener.accept().await.unwrap();
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });

    Url::parse(&format!("http://{address}/request.jwt")).unwrap()
}

#[path = "network/backchannel.rs"]
mod backchannel;

#[path = "network/password_breach.rs"]
mod password_breach;
