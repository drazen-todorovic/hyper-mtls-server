use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use clap::Parser;
use hyper_mtls_server::MtlServer;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
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
            let tower_service = Router::new().route("/", get(handler));

            tokio::spawn(async move {
                let accept_result = acceptor.accept(stream).await;
                let hyper_service = TowerToHyperService::new(tower_service);

                match accept_result {
                    Ok(stream) => {
                        let io = TokioIo::new(stream);
                        if let Err(err) =
                            hyper_util::server::conn::auto::Builder::new(
                                TokioExecutor::new(),
                            )
                            .serve_connection(io, hyper_service)
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

async fn handler() -> impl IntoResponse {
    "Hello from axum mTLS"
}
