use std::{io, net::SocketAddr, sync::Arc};

use actix_cors::Cors;
use actix_web::{App, Error as HttpError, HttpResponse, HttpServer, http, middleware, web};
use common::{
    rpc_primitives::{RpcConfig, message::Message},
    transaction::NSSATransaction,
};
use futures::{Future, FutureExt as _};
use log::info;
use mempool::MemPoolHandle;
#[cfg(not(feature = "standalone"))]
use sequencer_core::SequencerCore;
#[cfg(feature = "standalone")]
use sequencer_core::SequencerCoreWithMockClients as SequencerCore;
use tokio::sync::Mutex;

#[cfg(not(feature = "standalone"))]
use super::JsonHandler;
use crate::process::Process;

pub const SHUTDOWN_TIMEOUT_SECS: u64 = 10;

pub const NETWORK: &str = "network";

#[cfg(feature = "standalone")]
type JsonHandler = super::JsonHandlerWithMockClients;

pub(crate) fn rpc_handler<P: Process>(
    message: web::Json<Message>,
    handler: web::Data<P>,
) -> impl Future<Output = Result<HttpResponse, HttpError>> {
    let response = async move {
        let message = handler.process(message.0).await?;
        Ok(HttpResponse::Ok().json(&message))
    };
    response.boxed()
}

fn get_cors(cors_allowed_origins: &[String]) -> Cors {
    let mut cors = Cors::permissive();
    if cors_allowed_origins != ["*".to_owned()] {
        for origin in cors_allowed_origins {
            cors = cors.allowed_origin(origin);
        }
    }
    cors.allowed_methods(vec!["GET", "POST"])
        .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
        .allowed_header(http::header::CONTENT_TYPE)
        .max_age(3600)
}

pub async fn new_http_server(
    config: RpcConfig,
    seuquencer_core: Arc<Mutex<SequencerCore>>,
    mempool_handle: MemPoolHandle<NSSATransaction>,
) -> io::Result<(actix_web::dev::Server, SocketAddr)> {
    let RpcConfig {
        addr,
        cors_allowed_origins,
        limits_config,
    } = config;
    info!(target:NETWORK, "Starting HTTP server at {addr}");
    let max_block_size = seuquencer_core
        .lock()
        .await
        .sequencer_config()
        .max_block_size
        .as_u64()
        .try_into()
        .expect("`max_block_size` is expected to fit into usize");
    let handler = web::Data::new(JsonHandler {
        sequencer_state: Arc::clone(&seuquencer_core),
        mempool_handle,
        max_block_size,
    });

    // HTTP server
    let http_server = HttpServer::new(move || {
        let json_limit = limits_config
            .json_payload_max_size
            .as_u64()
            .try_into()
            .expect("`json_payload_max_size` is expected to fit into usize");
        App::new()
            .wrap(get_cors(&cors_allowed_origins))
            .app_data(handler.clone())
            .app_data(web::JsonConfig::default().limit(json_limit))
            .wrap(middleware::Logger::default())
            .service(web::resource("/").route(web::post().to(rpc_handler::<JsonHandler>)))
    })
    .bind(addr)?
    .shutdown_timeout(SHUTDOWN_TIMEOUT_SECS)
    .disable_signals();

    let [final_addr] = http_server
        .addrs()
        .try_into()
        .expect("Exactly one address bound is expected for sequencer HTTP server");

    info!(target:NETWORK, "HTTP server started at {final_addr}");

    Ok((http_server.run(), final_addr))
}
