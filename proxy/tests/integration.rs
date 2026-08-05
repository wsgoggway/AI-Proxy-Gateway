use http_body_util::BodyExt;
use hyper::Request;
/// Интеграционный тест: запуск TLS-сервера и проверка ответа
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

fn init_crypto() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install ring crypto provider");
}

/// Генерирует самоподписанный сертификат и ключ, сохраняет во временную директорию
fn generate_cert_and_key(dir: &TempDir) -> (PathBuf, PathBuf) {
    let key_pair = KeyPair::generate().expect("generate key pair");
    let params = CertificateParams::new(["localhost".to_string()]).expect("certificate params");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");

    let cert_path = dir.path().join("server.pem");
    let key_path = dir.path().join("server.key");

    std::fs::write(&cert_path, cert.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");

    (cert_path, key_path)
}

/// Загружает PEM-сертификат(ы) и возвращает список rustls CertificateDer
fn load_certs(path: &PathBuf) -> Vec<CertificateDer<'static>> {
    let pem = std::fs::read(path).expect("read cert");
    rustls_pemfile::certs(&mut pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse certs")
}

/// Загружает PEM-ключ и возвращает PrivateKeyDer
fn load_key(path: &PathBuf) -> PrivateKeyDer<'static> {
    let pem = std::fs::read(path).expect("read key");
    rustls_pemfile::private_key(&mut pem.as_slice())
        .expect("parse key")
        .expect("key found")
}

/// Создаёт TLS-коннектор, который доверяет заданному CA-сертификату
fn make_tls_connector(ca_cert: CertificateDer<'static>) -> TlsConnector {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca_cert).expect("add ca cert");

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    TlsConnector::from(Arc::new(config))
}

/// Запускает прокси-сервер на динамическом порту, возвращает адрес и JoinHandle
async fn start_proxy(
    cert_path: PathBuf,
    key_path: PathBuf,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    // Загружаем TLS-конфиг
    let certs = load_certs(&cert_path);
    let key = load_key(&key_path);

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config");

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    // Привязываемся к случайному порту
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let handle = tokio::spawn(async move {
        #[allow(clippy::while_let_loop)] // mock server loop: accept until dropped
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        if let Ok(tls_stream) = acceptor.accept(stream).await {
                            let io = TokioIo::new(tls_stream);
                            let svc = hyper::service::service_fn(|_req: Request<Incoming>| async {
                                Ok::<_, hyper::Error>(
                                    hyper::Response::builder()
                                        .status(200)
                                        .body("Proxy OK".to_string())
                                        .unwrap(),
                                )
                            });
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, svc)
                                .await;
                        }
                    });
                }
                Err(_) => break,
            }
        }
    });

    (addr, handle)
}

#[tokio::test]
async fn test_tls_server_startup() {
    init_crypto();

    let dir = TempDir::new().expect("temp dir");
    let (cert_path, key_path) = generate_cert_and_key(&dir);

    let certs = load_certs(&cert_path);
    let ca_cert = certs.into_iter().next().expect("at least one cert");

    // Запускаем прокси
    let (addr, _handle) = start_proxy(cert_path, key_path).await;

    // Подключаемся TLS-клиентом
    let connector = make_tls_connector(ca_cert);
    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let server_name = ServerName::try_from("localhost")
        .expect("server name")
        .to_owned();
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls connect");
    let io = TokioIo::new(tls_stream);

    // Отправляем HTTP-запрос
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("http handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .uri("https://localhost/")
        .body("".to_string())
        .expect("build request");

    let resp = sender.send_request(req).await.expect("send request");
    assert_eq!(resp.status(), 200);

    // Читаем тело
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes();
    let body = String::from_utf8(body_bytes.to_vec()).expect("utf8");
    assert_eq!(body, "Proxy OK");
}
