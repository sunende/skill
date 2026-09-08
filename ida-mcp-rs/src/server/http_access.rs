//! HTTP access checks around the rmcp Streamable HTTP service.

use bytes::Bytes;
use http::{
    header::{HOST, ORIGIN},
    HeaderMap, Request, Response, StatusCode,
};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use std::collections::HashSet;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_service::Service;

type AccessResponse = Response<BoxBody<Bytes, Infallible>>;
type AccessError = Box<AccessResponse>;

#[derive(Clone)]
pub struct HttpAccessService<S> {
    inner: S,
    policy: Arc<HttpAccessPolicy>,
}

impl<S> HttpAccessService<S> {
    pub fn new(inner: S, policy: HttpAccessPolicy) -> Self {
        Self {
            inner,
            policy: Arc::new(policy),
        }
    }
}

impl<B, S> Service<Request<B>> for HttpAccessService<S>
where
    B: http_body::Body + Send + 'static,
    B::Error: std::fmt::Display,
    S: Service<Request<B>, Response = AccessResponse, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = AccessResponse;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let policy = self.policy.clone();
        let mut inner = self.inner.clone();
        Box::pin(async move {
            if let Err(response) = policy.validate(req.headers()) {
                return Ok(*response);
            }
            inner.call(req).await
        })
    }
}

#[derive(Clone, Debug)]
pub struct HttpAccessPolicy {
    bind_addr: SocketAddr,
    allowed_origins: Arc<HashSet<String>>,
    allowed_hosts: HostAllowList,
}

impl HttpAccessPolicy {
    pub fn from_cli(
        bind_addr: SocketAddr,
        allow_origin: &[String],
        allow_host: Option<&[String]>,
    ) -> Self {
        Self {
            bind_addr,
            allowed_origins: Arc::new(clean_allowlist(allow_origin).into_iter().collect()),
            allowed_hosts: HostAllowList::from_cli(allow_host),
        }
    }

    pub fn host_check_disabled(&self) -> bool {
        matches!(self.allowed_hosts, HostAllowList::Any)
    }

    pub fn host_policy_summary(&self) -> String {
        match &self.allowed_hosts {
            HostAllowList::Any => "disabled; all Host values are allowed".to_string(),
            HostAllowList::Restricted(extra_hosts) if extra_hosts.is_empty() => {
                format!("bind-derived IP hosts for {}", self.bind_addr)
            }
            HostAllowList::Restricted(extra_hosts) => {
                let extra = extra_hosts
                    .iter()
                    .map(NormalizedAuthority::display)
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "bind-derived IP hosts for {}; extra allowlist: {}",
                    self.bind_addr, extra
                )
            }
        }
    }

    fn validate(&self, headers: &HeaderMap) -> Result<(), AccessError> {
        self.validate_origin(headers)?;
        self.validate_host(headers)?;
        Ok(())
    }

    fn validate_origin(&self, headers: &HeaderMap) -> Result<(), AccessError> {
        let Some(origin) = headers.get(ORIGIN) else {
            return Ok(());
        };
        let origin = origin
            .to_str()
            .map_err(|_| access_error(StatusCode::BAD_REQUEST, "Bad Request: invalid Origin"))?;
        if self.allowed_origins.contains(origin) {
            return Ok(());
        }

        Err(access_error(
            StatusCode::FORBIDDEN,
            "Forbidden: Origin is not allowed",
        ))
    }

    fn validate_host(&self, headers: &HeaderMap) -> Result<(), AccessError> {
        let host = parse_host_header(headers)?;
        if self.host_check_disabled() {
            return Ok(());
        }

        if self.host_allowed_by_bind(&host) || self.allowed_hosts.contains(&host) {
            return Ok(());
        }

        Err(access_error(
            StatusCode::FORBIDDEN,
            format!(
                "Forbidden: Host header '{}' is not allowed; {}",
                host.display(),
                self.host_policy_summary()
            ),
        ))
    }

    fn host_allowed_by_bind(&self, host: &NormalizedAuthority) -> bool {
        if !port_matches(host.port, self.bind_addr.port()) {
            return false;
        }

        let bind_ip = self.bind_addr.ip();
        if host.host == "localhost" {
            return bind_ip.is_loopback() || bind_ip.is_unspecified();
        }

        let Ok(host_ip) = host.host.parse::<IpAddr>() else {
            return false;
        };

        if bind_ip.is_unspecified() {
            return true;
        }
        if bind_ip.is_loopback() {
            return host_ip.is_loopback();
        }
        host_ip == bind_ip
    }
}

fn port_matches(host_port: Option<u16>, bind_port: u16) -> bool {
    match host_port {
        Some(port) => port == bind_port,
        None => true,
    }
}

fn text_response(message_status: StatusCode, message: impl Into<String>) -> AccessResponse {
    let mut response = Response::new(Full::new(Bytes::from(message.into())).boxed());
    *response.status_mut() = message_status;
    response
}

fn access_error(message_status: StatusCode, message: impl Into<String>) -> AccessError {
    Box::new(text_response(message_status, message))
}

fn clean_allowlist(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_host_header(headers: &HeaderMap) -> Result<NormalizedAuthority, AccessError> {
    let Some(host) = headers.get(HOST) else {
        return Err(access_error(
            StatusCode::BAD_REQUEST,
            "Bad Request: missing Host header",
        ));
    };
    let host = host
        .to_str()
        .map_err(|_| access_error(StatusCode::BAD_REQUEST, "Bad Request: invalid Host header"))?;
    http::uri::Authority::try_from(host)
        .map(|authority| normalize_authority(authority.host(), authority.port_u16()))
        .map_err(|_| access_error(StatusCode::BAD_REQUEST, "Bad Request: invalid Host header"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum HostAllowList {
    Any,
    Restricted(Vec<NormalizedAuthority>),
}

impl HostAllowList {
    fn from_cli(allow_host: Option<&[String]>) -> Self {
        let Some(values) = allow_host else {
            return Self::Restricted(Vec::new());
        };

        let mut hosts = Vec::new();
        for value in values.iter().map(|value| value.trim()) {
            if value == "*" {
                return Self::Any;
            }
            if value.is_empty() {
                continue;
            }
            if let Some(authority) = parse_allowed_authority(value) {
                hosts.push(authority);
            }
        }

        if hosts.is_empty() {
            return Self::Any;
        }
        Self::Restricted(hosts)
    }

    fn contains(&self, host: &NormalizedAuthority) -> bool {
        match self {
            Self::Any => true,
            Self::Restricted(allowed_hosts) => allowed_hosts.iter().any(|allowed| {
                allowed.host == host.host
                    && match allowed.port {
                        Some(port) => host.port == Some(port),
                        None => true,
                    }
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NormalizedAuthority {
    host: String,
    port: Option<u16>,
}

impl NormalizedAuthority {
    fn display(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{}", self.host, port),
            None => self.host.clone(),
        }
    }
}

fn normalize_authority(host: &str, port: Option<u16>) -> NormalizedAuthority {
    NormalizedAuthority {
        host: normalize_host(host),
        port,
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_matches('[')
        .trim_matches(']')
        .to_ascii_lowercase()
}

fn parse_allowed_authority(allowed: &str) -> Option<NormalizedAuthority> {
    let allowed = allowed.trim();
    if allowed.is_empty() {
        return None;
    }

    if let Ok(authority) = http::uri::Authority::try_from(allowed) {
        return Some(normalize_authority(authority.host(), authority.port_u16()));
    }

    Some(normalize_authority(allowed, None))
}

#[cfg(test)]
mod tests {
    use crate::server::http_access::HttpAccessPolicy;
    use http::HeaderMap;
    use std::net::SocketAddr;

    fn policy(bind: &str, allowed_hosts: Option<&[&str]>) -> HttpAccessPolicy {
        let bind_addr = bind.parse::<SocketAddr>().expect("valid bind address");
        let origins = Vec::new();
        let hosts = allowed_hosts.map(|hosts| {
            hosts
                .iter()
                .map(|host| (*host).to_string())
                .collect::<Vec<_>>()
        });
        HttpAccessPolicy::from_cli(bind_addr, &origins, hosts.as_deref())
    }

    fn headers(host: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, host.parse().expect("valid host"));
        headers
    }

    #[test]
    fn wildcard_bind_allows_lan_ip_literal_hosts() {
        let policy = policy("0.0.0.0:8765", None);
        assert!(policy.validate(&headers("10.10.10.101:8765")).is_ok());
    }

    #[test]
    fn wildcard_bind_allows_lan_ip_even_with_extra_allow_host() {
        let policy = policy("0.0.0.0:8765", Some(&["10.10.10.100"]));
        assert!(policy.validate(&headers("10.10.10.101:8765")).is_ok());
    }

    #[test]
    fn wildcard_bind_rejects_unlisted_dns_host() {
        let policy = policy("0.0.0.0:8765", None);
        let response = policy
            .validate(&headers("example.com:8765"))
            .expect_err("unlisted DNS host should be rejected");
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn explicit_dns_host_allows_matching_host() {
        let policy = policy("0.0.0.0:8765", Some(&["ida-box.local"]));
        assert!(policy.validate(&headers("ida-box.local:8765")).is_ok());
    }

    #[test]
    fn loopback_bind_rejects_lan_ip_literal_host() {
        let policy = policy("127.0.0.1:8765", None);
        let response = policy
            .validate(&headers("10.10.10.101:8765"))
            .expect_err("LAN host should not be valid for loopback bind");
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn wildcard_allow_host_disables_host_check() {
        let policy = policy("127.0.0.1:8765", Some(&["*"]));
        assert!(policy.host_check_disabled());
        assert!(policy.validate(&headers("example.com:9999")).is_ok());
    }

    #[test]
    fn empty_allow_host_disables_host_check() {
        let policy = policy("127.0.0.1:8765", Some(&[""]));
        assert!(policy.host_check_disabled());
        assert!(policy.validate(&headers("example.com:9999")).is_ok());
    }

    #[test]
    fn disabled_host_check_still_requires_host_header() {
        let policy = policy("127.0.0.1:8765", Some(&["*"]));
        let response = policy
            .validate(&HeaderMap::new())
            .expect_err("missing Host remains a bad request");
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }
}
