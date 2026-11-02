use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

use reqwest::Client;
use salvo::Service;
use serde_json::Value;

struct Processes {
    login: Child,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Processes {
    fn drop(&mut self) {
        let _ = self.login.kill();
        let _ = self.login.wait();
        self.server.abort();
    }
}

/// Exercise the built Login BFF against the real installation service and database.
pub async fn verify(node: &str, app: Service, workload_token: &str, input: &Value) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal = format!("http://{}", listener.local_addr().unwrap());
    let acceptor = salvo::conn::tcp::TcpAcceptor::try_from(listener).unwrap();
    let server = tokio::spawn(async move {
        salvo::Server::new(acceptor).serve(app).await;
    });
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let login = Command::new(node)
        .arg("production-server.mjs")
        .current_dir("apps/login")
        .env("NODE_ENV", "production")
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("IDENTITY_INTERNAL_API_URL", internal)
        .env("IDENTITY_INTERNAL_API_ALLOW_HTTP", "true")
        .env("IDENTITY_WORKLOAD_TOKEN", workload_token)
        .env(
            "IDENTITY_LOGIN_SESSION_SECRET",
            "local-installation-test-cookie-sealing-secret-0123456789",
        )
        .env_remove("IDENTITY_WORKLOAD_TOKEN_FILE")
        .env_remove("IDENTITY_API_URL")
        .env_remove("IDENTITY_PUBLIC_APP_URL")
        .env_remove("NITRO_SSL_CERT_FILE")
        .env_remove("NITRO_SSL_KEY_FILE")
        .env_remove("NITRO_SSL_CERT")
        .env_remove("NITRO_SSL_KEY")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _processes = Processes { login, server };
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let origin = format!("http://127.0.0.1:{port}");
    let mut ready = false;
    for _ in 0..100 {
        if client
            .get(format!("{origin}/health/ready"))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        ready,
        "production Login must serve installation without public-address environment variables"
    );
    let page = client
        .get(format!("{origin}/install"))
        .header("X-Forwarded-Proto", "https")
        .header("Accept-Language", "zh-CN")
        .send()
        .await
        .unwrap();
    assert!(page.status().is_success());
    let html = page.text().await.unwrap();
    assert!(
        html.contains("安装 Identity"),
        "production installer did not render"
    );
    assert!(html.contains(&format!("https://127.0.0.1:{port}/console/")));
    let post = |value: &Value| {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in value.as_object().unwrap() {
            form.append_pair(key, value.as_str().unwrap());
        }
        form.append_pair("confirm_password", value["password"].as_str().unwrap());
        client
            .post(format!("{origin}/install"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("X-Forwarded-Proto", "https")
            .header("X-Enhanced-Form", "1")
            .header("Accept-Language", "zh-CN")
            .body(form.finish())
    };
    let rejected = post(input).send().await.unwrap();
    assert!(rejected.status().is_success());
    let cookie = rejected
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(
        rejected.json::<Value>().await.unwrap()["redirect"],
        "/install"
    );
    let html = client
        .get(format!("{origin}/install"))
        .header("X-Forwarded-Proto", "https")
        .header("Accept-Language", "zh-CN")
        .header("Cookie", cookie)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        html.contains("邮箱地址格式无效"),
        "field validation must render in Chinese"
    );
    assert!(
        html.contains("installverify-owner"),
        "failed submission must retain non-secret fields"
    );
    let mut corrected = input.clone();
    corrected["email"] = Value::String("installverify-owner@example.test".to_owned());
    let response = post(&corrected).send().await.unwrap();
    assert!(response.status().is_success());
    assert_eq!(
        response.json::<Value>().await.unwrap()["redirect"],
        "/",
        "corrected installer form must submit successfully"
    );
    let ready = client
        .get(format!("{origin}/health/ready"))
        .send()
        .await
        .unwrap();
    assert!(
        ready.status().is_success(),
        "Login must load persisted runtime addresses after installation"
    );
}
