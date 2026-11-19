//! Real HTTP transport behavior with local protocol peers.
use identity_application::openid_connect::remote::{
    DEFAULT_REMOTE_DOCUMENT_MAX_BYTES, RemoteFetchError, fetch_document_after_url_validation,
};
use reqwest::{Client, redirect::Policy};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
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
    assert!(
        matches!(error, RemoteFetchError::TooLarge),
        "unexpected error: {error:?}"
    );
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

    assert!(
        matches!(error, RemoteFetchError::NotOk),
        "unexpected error: {error:?}"
    );
}
async fn read_http_request_head(stream: &mut TcpStream) {
    let mut request = Vec::new();
    while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await.unwrap();
        assert!(
            read > 0,
            "client closed before sending HTTP request headers"
        );
        request.extend_from_slice(&chunk[..read]);
    }
}
async fn spawn_chunked_response_server(chunks: Vec<Vec<u8>>, keep_open_for: Duration) -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_http_request_head(&mut stream).await;
        if stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n",
            )
            .await
            .is_err()
        {
            return;
        }

        for chunk in chunks {
            if stream
                .write_all(format!("{:X}\r\n", chunk.len()).as_bytes())
                .await
                .is_err()
                || stream.write_all(&chunk).await.is_err()
                || stream.write_all(b"\r\n").await.is_err()
            {
                return;
            }
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
        read_http_request_head(&mut stream).await;
        let response = format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;

        let (mut stream, _) = listener.accept().await.unwrap();
        read_http_request_head(&mut stream).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await;
        let _ = stream.shutdown().await;
    });

    Url::parse(&format!("http://{address}/request.jwt")).unwrap()
}

#[path = "network/backchannel.rs"]
mod backchannel;

#[path = "network/password_breach.rs"]
mod password_breach;
