mod body;
mod chat;
mod dispatch;
mod handlers;
mod local;
mod proxy;

use anyhow::{Context, Result as AnyResult};
use pingora::{
    proxy::http_proxy_service,
    server::{configuration::Opt as PingoraOpt, Server},
};
use tracing::info;

use crate::{
    config::{Config, RouteRule, Upstream},
    state::AppState,
};

#[derive(Debug, Default, Clone)]
pub(crate) struct ProxyContext {
    request_id: String,
    trace_id: Option<String>,
    tenant_id: Option<String>,
    route: Option<RouteRule>,
    upstream: Option<Upstream>,
    upstream_url: Option<String>,
    target_path_query: Option<String>,
    original_host: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct FerroGateway {
    state: AppState,
}

pub(crate) fn serve(config: Config) -> AnyResult<()> {
    let listen = config.listen.clone();
    let state = AppState::new(config);
    let gateway = FerroGateway { state };

    let mut server =
        Server::new(Some(PingoraOpt::default())).context("failed to create Pingora server")?;
    server.bootstrap();

    let mut service = http_proxy_service(&server.configuration, gateway);
    service.add_tcp(&listen);
    server.add_service(service);

    info!(listen = %listen, runtime = "pingora", "FerroGate Pingora gateway listening");
    server.run_forever();
}
