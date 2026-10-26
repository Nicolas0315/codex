use super::*;
use pretty_assertions::assert_eq;
use tokio::runtime::Builder;

#[test]
fn custom_ca_http_client_verifies_the_loopback_server_certificate() {
    use std::io::Read;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::Arc;

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    let server_config = Arc::new(server_config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut accepted = Vec::new();
        for _ in 0..2 {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let connection = rustls::ServerConnection::new(Arc::clone(&server_config)).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut request = [0; 1024];
            let verified = stream.read(&mut request).is_ok();
            if verified {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .unwrap();
            }
            accepted.push(verified);
        }
        accepted
    });
    let directory = tempfile::tempdir().unwrap();
    let ca_path = directory.path().join("ca.pem");
    fs::write(&ca_path, cert.pem()).unwrap();
    let mut tls = OtelTlsConfig {
        ca_certificate: Some(AbsolutePathBuf::try_from(ca_path).unwrap()),
        ..OtelTlsConfig::default()
    };
    let client = build_http_client(&tls, OTEL_EXPORTER_OTLP_TIMEOUT).unwrap();
    assert_eq!(
        client
            .get(format!("https://{address}"))
            .send()
            .unwrap()
            .status(),
        200
    );

    let unrelated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let unrelated_path = directory.path().join("unrelated.pem");
    fs::write(&unrelated_path, unrelated.cert.pem()).unwrap();
    tls.ca_certificate = Some(AbsolutePathBuf::try_from(unrelated_path).unwrap());
    let client = build_http_client(&tls, OTEL_EXPORTER_OTLP_TIMEOUT).unwrap();
    assert!(
        client
            .get(format!("https://{address}"))
            .send()
            .unwrap_err()
            .is_connect()
    );
    assert_eq!(server.join().unwrap(), vec![true, false]);
}

#[test]
fn mtls_clients_reject_cleartext_before_connecting() {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let certificate = directory.path().join("client.pem");
    let private_key = directory.path().join("client-key.pem");
    fs::write(&certificate, cert.pem()).unwrap();
    fs::write(&private_key, signing_key.serialize_pem()).unwrap();
    let tls = OtelTlsConfig {
        ca_certificate: None,
        client_certificate: Some(AbsolutePathBuf::try_from(certificate).unwrap()),
        client_private_key: Some(AbsolutePathBuf::try_from(private_key).unwrap()),
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let client = build_http_client(&tls, OTEL_EXPORTER_OTLP_TIMEOUT).unwrap();
    assert!(client.get(&url).send().unwrap_err().is_builder());
    let client = build_async_http_client(Some(&tls), OTEL_EXPORTER_OTLP_TIMEOUT).unwrap();
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    assert!(
        runtime
            .block_on(client.get(&url).send())
            .unwrap_err()
            .is_builder()
    );
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}
