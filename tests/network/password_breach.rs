use identity_application::auth::password_policy::BreachedPasswordChecker;
use identity_infrastructure::{
    auth::breached_password::PwnedPasswordChecker, crypto::tls::generate_self_signed_tls_cert,
};
use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod},
    x509::X509,
};
use std::{
    io::{Read, Write},
    time::Duration,
};

#[tokio::test]
async fn sends_only_the_range_prefix_and_fails_closed_on_http_errors() {
    let password = "a unique password for transport test";
    let hash: String = openssl::sha::sha1(password.as_bytes())
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    let (cert, key) = generate_self_signed_tls_cert("localhost").unwrap();
    let mut tls = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    tls.set_certificate(&X509::from_pem(cert.as_bytes()).unwrap())
        .unwrap();
    tls.set_private_key(&PKey::private_key_from_pem(key.as_bytes()).unwrap())
        .unwrap();
    tls.check_private_key().unwrap();
    let tls = std::sync::Arc::new(tls.build());
    for status in [200, 503] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let expected = hash.clone();
        let tls = tls.clone();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut socket = tls.accept(socket).unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                assert_eq!(socket.read(&mut byte).unwrap(), 1);
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with(&format!("GET /range/{} HTTP/1.1", &expected[..5])));
            assert!(request.to_lowercase().contains("add-padding: true"));
            assert!(!request.contains(password));
            assert!(!request.contains(&expected[5..]));
            let body = format!("{}:1\r\n", &expected[5..]);
            write!(
                socket,
                "HTTP/1.1 {status} test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .add_root_certificate(reqwest::Certificate::from_pem(cert.as_bytes()).unwrap())
            .build()
            .unwrap();
        let checker = PwnedPasswordChecker::with_http_client(
            client,
            format!("https://localhost:{}/range/", address.port())
                .parse()
                .unwrap(),
        )
        .unwrap();
        let result = checker.is_breached(password).await;
        server.join().unwrap();
        if status == 200 {
            assert!(result.unwrap());
        } else {
            assert!(result.is_err());
        }
    }
}
