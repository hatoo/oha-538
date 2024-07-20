use std::{
    io::{stdout, Write},
    sync::Arc,
};

use clap::Parser;
use futures::StreamExt;
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Method, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;

#[derive(Debug, Parser)]
struct Opts {
    uri: Uri,
    #[clap(short)]
    n: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    let uri = opts.uri;

    let tcp = TcpStream::connect((uri.host().unwrap(), uri.port_u16().unwrap_or(443))).await?;

    tcp.set_nodelay(true)?;

    let mut root_cert_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs()? {
        root_cert_store.add(cert).ok(); // ignore error
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let domain = rustls_pki_types::ServerName::try_from(uri.host().unwrap())?;
    let tls = connector.connect(domain.to_owned(), tcp).await?;

    let builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    let (mut send_request, conn) = builder.handshake(TokioIo::new(tls)).await?;
    tokio::spawn(conn);

    for _ in 0..opts.n {
        let req = hyper::http::Request::builder()
            .method(Method::GET)
            .uri(uri.clone())
            .body(Empty::<Bytes>::new())?;

        let res = send_request.send_request(req).await?;

        let (parts, body) = res.into_parts();
        assert_eq!(parts.status, hyper::StatusCode::OK);

        let mut body_stream = body.into_data_stream();
        while let Some(_chunk) = body_stream.next().await {}
        print!(".");
        stdout().flush()?;
    }

    Ok(())
}
