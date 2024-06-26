use clap::Parser;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_mtls_server::MtlServer;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::error::Error;
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Config {
    #[clap(env)]
    #[arg(short, long, value_name = "PORT", default_value = "3002")]
    port: u32,

    #[clap(env)]
    #[arg(long, value_name = "FILE")]
    server_certificate_path: String,

    #[clap(env)]
    #[arg(long, value_name = "FILE")]
    server_private_key_path: String,

    #[clap(env)]
    #[arg(long, value_name = "FILE")]
    client_ca_certificate_path: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::parse();

    let socket = TcpListener::bind(format!("0.0.0.0:{}", config.port)).await?;
    let client_ca_cert = Box::from(config.client_ca_certificate_path);
    let server_crt = Box::from(config.server_certificate_path);
    let server_key = Box::from(config.server_private_key_path);
    let server = MtlServer::new(server_crt, server_key, client_ca_cert);

    let result = server
        .serve(socket, |stream, acceptor| {
            tokio::spawn(async move {
                let accept_result = acceptor.accept(stream).await;
                match accept_result {
                    Ok(stream) => {
                        let io = TokioIo::new(stream);
                        if let Err(err) = http1::Builder::new()
                            .serve_connection(io, service_fn(handler))
                            .await
                        {
                            eprintln!(
                                "error while serving http connection: {:?}",
                                err
                            );
                        }
                    }
                    Err(err) => {
                        eprintln!("error accepting mTLS: {:?}", err);
                    }
                }
            });
        })
        .await;

    if let Err(err) = result {
        eprintln!("error: {:?}", err);
    }

    Ok(())
}

async fn handler(
    _req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::builder()
        .status(200)
        .body("Hello from mTLS".into())
        .unwrap())
}
