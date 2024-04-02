use crate::Error::{
    CertExtractError, CertFileReadError, ClientVerifierBuildError,
    PrivateKeyExtractError, PrivateKeyFileReadError, PrivateKeyItemEmptyError,
    ServerConfigError, TrustStoreError,
};
use rustls::server::{VerifierBuilderError, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::ops::Deref;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

#[derive(Clone, Debug)]
pub struct Protocol(&'static str);

impl Protocol {
    pub const HTTP_1: Protocol = Protocol("http/1.1");
    pub const HTTP_2: Protocol = Protocol("h2");
}

#[derive(thiserror::Error, Debug)]
#[error("{msg}")]
pub struct CertErrorDetail {
    msg: String,
    #[source]
    source: std::io::Error,
}

impl CertErrorDetail {
    fn new(msg: String, source: std::io::Error) -> Self {
        Self { msg, source }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed reading certificate from file")]
    CertFileReadError(#[source] CertErrorDetail),

    #[error("failed extracting certificate from file")]
    CertExtractError(#[source] CertErrorDetail),

    #[error("failed reading private key from file")]
    PrivateKeyFileReadError(#[source] std::io::Error),

    #[error("failed extracting private key from file")]
    PrivateKeyExtractError(#[source] std::io::Error),

    #[error("private key item is empty")]
    PrivateKeyItemEmptyError,

    #[error("failed adding certificate to the cert store")]
    TrustStoreError(#[source] rustls::Error),

    #[error("failed building server tsl config")]
    ServerConfigError(#[source] rustls::Error),

    #[error("failed to build client verifier")]
    ClientVerifierBuildError(#[source] VerifierBuilderError),
}

pub struct MtlServer {
    server_cert_path: Box<str>,
    server_key_path: Box<str>,
    client_ca_cert_path: Box<str>,
    protocols: Option<Box<[Protocol]>>,
}

impl MtlServer {
    pub fn new(
        server_cert_path: Box<str>,
        server_key_path: Box<str>,
        client_ca_cert_path: Box<str>,
    ) -> Self {
        let protocols =
            Some(vec![Protocol::HTTP_1, Protocol::HTTP_2].into_boxed_slice());
        Self {
            server_cert_path,
            server_key_path,
            client_ca_cert_path,
            protocols,
        }
    }

    pub fn new_with_protocols(
        server_cert_path: Box<str>,
        server_key_path: Box<str>,
        client_ca_cert_path: Box<str>,
        protocols: Box<[Protocol]>,
    ) -> Self {
        let protocols = Some(protocols);
        Self {
            server_cert_path,
            server_key_path,
            client_ca_cert_path,
            protocols,
        }
    }

    fn load_cert(path: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
        let cert_file = File::open(path).map_err(|x| {
            let msg = format!("failed to read certificate form path: {}", path);
            CertFileReadError(CertErrorDetail::new(msg, x))
        })?;
        let mut reader = BufReader::new(cert_file);
        let certs: std::io::Result<Vec<CertificateDer>> =
            rustls_pemfile::certs(&mut reader).collect();

        let certs = match certs {
            Ok(certs) => certs,
            Err(err) => {
                return Err(CertExtractError(CertErrorDetail::new(
                    "Error reading certificate".into(),
                    err,
                )));
            }
        };
        Ok(certs)
    }

    fn load_server_cert(&self) -> Result<Vec<CertificateDer<'static>>, Error> {
        Self::load_cert(&self.server_cert_path)
    }

    fn load_client_ca_cert(
        &self,
    ) -> Result<Vec<CertificateDer<'static>>, Error> {
        Self::load_cert(&self.client_ca_cert_path)
    }

    fn load_server_key(&self) -> Result<PrivateKeyDer<'static>, Error> {
        let key_file = File::open(self.server_key_path.deref())
            .map_err(PrivateKeyFileReadError)?;
        let mut reader = BufReader::new(key_file);

        let item = rustls_pemfile::private_key(&mut reader)
            .map_err(PrivateKeyExtractError)?
            .ok_or_else(|| PrivateKeyItemEmptyError)?;

        Ok(item)
    }

    fn create_tls_config(&self) -> Result<ServerConfig, Error> {
        let mut roots = RootCertStore::empty();

        let client_ca_certs = self.load_client_ca_cert()?;
        for cert in client_ca_certs {
            roots.add(cert).map_err(TrustStoreError)?;
        }

        let client_verifier = WebPkiClientVerifier::builder(roots.into())
            .build()
            .map_err(ClientVerifierBuildError)?;
        let server_cert = self.load_server_cert()?;
        let server_key = self.load_server_key()?;

        let mut config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_cert, server_key)
            .map_err(ServerConfigError)?;

        if let Some(protocols) = &self.protocols {
            let protocols: Vec<Vec<u8>> =
                protocols.iter().map(|x| x.0.as_bytes().to_vec()).collect();
            config.alpn_protocols = protocols;
        }

        Ok(config)
    }

    pub async fn serve<F>(
        &self,
        listener: TcpListener,
        callback: F,
    ) -> Result<(), Error>
    where
        F: Fn(TcpStream, TlsAcceptor) + 'static,
    {
        let config = self.create_tls_config()?;
        let acceptor = TlsAcceptor::from(Arc::new(config));

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let acceptor = acceptor.clone();
                    callback(stream, acceptor);
                }
                Err(err) => {
                    tracing::error!("server listener accep error: {:?}", err);
                }
            };
        }
    }
}
