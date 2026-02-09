#![allow(missing_docs)]
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    task::{Context, Poll},
};

use futures::{future::BoxFuture, FutureExt};
use hickory_resolver::TokioResolver;
use hyper::client::connect::dns::Name;
use rand::seq::SliceRandom;
use snafu::ResultExt;
use tokio::task::spawn_blocking;
use tower::Service;

// Re-export DnsResolver from vector-core for convenience
pub use vector_lib::config::DnsResolver;

/// Result of a DNS lookup, yielding socket addresses.
pub struct LookupIp(std::vec::IntoIter<SocketAddr>);

impl LookupIp {
    /// Create a LookupIp from an iterator of IpAddr.
    pub fn new_from_addrs<I: IntoIterator<Item = IpAddr>>(iter: I) -> Self {
        // Use dummy port 0 as placeholder - callers replace with actual port
        LookupIp(
            iter.into_iter()
                .map(|ip| SocketAddr::new(ip, 0))
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }

    /// Create a LookupIp from an iterator of SocketAddr.
    pub fn new_from_socket_addrs<I: IntoIterator<Item = SocketAddr>>(iter: I) -> Self {
        LookupIp(iter.into_iter().collect::<Vec<_>>().into_iter())
    }
}

impl Iterator for LookupIp {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// Simple DNS lookup result for backward compatibility, yielding IpAddr.
pub struct LookupIpSimple(std::vec::IntoIter<IpAddr>);

impl Iterator for LookupIpSimple {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// Backward-compatible function for simple DNS lookups using the native resolver.
/// This function is for code that doesn't need configurable DNS resolution.
pub async fn lookup_ip(name: String) -> Result<LookupIpSimple, DnsError> {
    // We need to add port with the name so that `to_socket_addrs`
    // resolves it properly. We will be discarding the port afterwards.
    //
    // Any port will do, but `9` is a well defined port for discarding
    // packets.
    let dummy_port = 9;
    // https://tools.ietf.org/html/rfc6761#section-6.3
    if name == "localhost" {
        // Not all operating systems support `localhost` as IPv6 `::1`, so
        // we resolving it to it's IPv4 value.
        Ok(LookupIpSimple(vec![Ipv4Addr::LOCALHOST.into()].into_iter()))
    } else {
        spawn_blocking(move || {
            let name_ref = match name.as_str() {
                // strip IPv6 prefix and suffix
                name if name.starts_with('[') && name.ends_with(']') => &name[1..name.len() - 1],
                name => name,
            };
            (name_ref, dummy_port)
                .to_socket_addrs()
                .map(|addrs| LookupIpSimple(addrs.map(|a| a.ip()).collect::<Vec<_>>().into_iter()))
        })
        .await
        .context(JoinSnafu)?
        .context(UnableLookupSnafu)
    }
}

/// Native DNS resolver using system's getaddrinfo.
#[derive(Debug, Clone, Copy)]
pub struct NativeResolver;

impl NativeResolver {
    async fn lookup_ip(self, name: String) -> Result<LookupIp, DnsError> {
        // We need to add port with the name so that `to_socket_addrs`
        // resolves it properly. We will be discarding the port afterwards.
        //
        // Any port will do, but `9` is a well defined port for discarding
        // packets.
        let dummy_port = 9;
        // https://tools.ietf.org/html/rfc6761#section-6.3
        if name == "localhost" {
            // Not all operating systems support `localhost` as IPv6 `::1`, so
            // we resolving it to it's IPv4 value.
            Ok(LookupIp(
                vec![SocketAddr::new(Ipv4Addr::LOCALHOST.into(), dummy_port)].into_iter(),
            ))
        } else {
            spawn_blocking(move || {
                let name_ref = match name.as_str() {
                    // strip IPv6 prefix and suffix
                    name if name.starts_with('[') && name.ends_with(']') => {
                        &name[1..name.len() - 1]
                    }
                    name => name,
                };
                (name_ref, dummy_port).to_socket_addrs()
            })
            .await
            .context(JoinSnafu)?
            .map(LookupIp::new_from_socket_addrs)
            .context(UnableLookupSnafu)
        }
    }
}

/// DNS resolver implementation that can be configured for different resolution strategies.
#[derive(Clone)]
pub enum Resolver {
    /// Native resolver using system's getaddrinfo
    Native(NativeResolver),
    /// Direct DNS resolver returning addresses in server order
    Direct(Arc<TokioResolver>),
    /// Direct DNS resolver returning addresses in random order
    Shuffle(Arc<TokioResolver>),
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native(_) => f.debug_tuple("Native").finish(),
            Self::Direct(_) => f.debug_tuple("Direct").finish(),
            Self::Shuffle(_) => f.debug_tuple("Shuffle").finish(),
        }
    }
}

impl Default for Resolver {
    fn default() -> Self {
        Self::Native(NativeResolver)
    }
}

impl Resolver {
    /// Create a new resolver from the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the hickory-resolver cannot be initialized with system configuration.
    pub fn from_config(config: DnsResolver) -> Result<Self, DnsError> {
        match config {
            DnsResolver::Native => Ok(Self::Native(NativeResolver)),
            DnsResolver::Direct | DnsResolver::Shuffle => {
                // Use system configuration from /etc/resolv.conf (or Windows registry)
                // The builder_tokio method reads system DNS configuration
                let resolver = TokioResolver::builder_tokio()
                    .map_err(|e| DnsError::HickoryResolve { source: e })?
                    .build();

                let resolver = Arc::new(resolver);
                match config {
                    DnsResolver::Direct => Ok(Self::Direct(resolver)),
                    DnsResolver::Shuffle => Ok(Self::Shuffle(resolver)),
                    DnsResolver::Native => unreachable!(),
                }
            }
        }
    }
}

impl Service<Name> for Resolver {
    type Response = LookupIp;
    type Error = DnsError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn call(&mut self, name: Name) -> Self::Future {
        match self {
            Self::Native(resolver) => resolver.lookup_ip(name.as_str().to_owned()).boxed(),
            Self::Direct(resolver) => {
                let resolver = Arc::clone(resolver);
                let name_str = name.as_str().to_owned();
                async move {
                    let lookup = resolver
                        .lookup_ip(&name_str)
                        .await
                        .map_err(|e| DnsError::HickoryResolve { source: e })?;
                    // Return all addresses in server order
                    Ok(LookupIp::new_from_addrs(lookup.iter()))
                }
                .boxed()
            }
            Self::Shuffle(resolver) => {
                let resolver = Arc::clone(resolver);
                let name_str = name.as_str().to_owned();
                async move {
                    let lookup = resolver
                        .lookup_ip(&name_str)
                        .await
                        .map_err(|e| DnsError::HickoryResolve { source: e })?;
                    let mut addrs: Vec<_> = lookup.iter().collect();
                    // Shuffle addresses for client-side load balancing
                    addrs.shuffle(&mut rand::rng());
                    Ok(LookupIp::new_from_addrs(addrs))
                }
                .boxed()
            }
        }
    }
}

#[derive(Debug, snafu::Snafu)]
pub enum DnsError {
    #[snafu(display("Unable to resolve name: {}", source))]
    UnableLookup { source: tokio::io::Error },
    #[snafu(display("Failed to join with resolving future: {}", source))]
    JoinError { source: tokio::task::JoinError },
    #[snafu(display("DNS resolution failed: {}", source))]
    HickoryResolve {
        source: hickory_resolver::ResolveError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn resolve_native(name: &str) -> bool {
        let mut resolver = Resolver::from_config(DnsResolver::Native).unwrap();
        Service::call(&mut resolver, name.parse().unwrap())
            .await
            .is_ok()
    }

    async fn resolve_direct(name: &str) -> bool {
        let mut resolver = Resolver::from_config(DnsResolver::Direct).unwrap();
        Service::call(&mut resolver, name.parse().unwrap())
            .await
            .is_ok()
    }

    async fn resolve_shuffle(name: &str) -> bool {
        let mut resolver = Resolver::from_config(DnsResolver::Shuffle).unwrap();
        Service::call(&mut resolver, name.parse().unwrap())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn native_resolve_example() {
        assert!(resolve_native("example.com").await);
    }

    #[tokio::test]
    async fn native_resolve_localhost() {
        assert!(resolve_native("localhost").await);
    }

    #[tokio::test]
    async fn native_resolve_ipv4() {
        assert!(resolve_native("10.0.4.0").await);
    }

    #[tokio::test]
    async fn native_resolve_ipv6() {
        assert!(resolve_native("::1").await);
    }

    #[tokio::test]
    async fn direct_resolve_example() {
        assert!(resolve_direct("example.com").await);
    }

    #[tokio::test]
    async fn shuffle_resolve_example() {
        assert!(resolve_shuffle("example.com").await);
    }

    #[tokio::test]
    async fn resolver_from_config_native() {
        let resolver = Resolver::from_config(DnsResolver::Native).unwrap();
        assert!(matches!(resolver, Resolver::Native(_)));
    }

    #[tokio::test]
    async fn resolver_from_config_direct() {
        let resolver = Resolver::from_config(DnsResolver::Direct).unwrap();
        assert!(matches!(resolver, Resolver::Direct(_)));
    }

    #[tokio::test]
    async fn resolver_from_config_shuffle() {
        let resolver = Resolver::from_config(DnsResolver::Shuffle).unwrap();
        assert!(matches!(resolver, Resolver::Shuffle(_)));
    }

    #[test]
    fn dns_resolver_config_default() {
        assert_eq!(DnsResolver::default(), DnsResolver::Native);
    }

    #[test]
    fn dns_resolver_config_parse() {
        #[derive(Debug, serde::Deserialize)]
        struct Wrapper {
            value: DnsResolver,
        }

        let config: Wrapper = toml::from_str(r#"value = "native""#).unwrap();
        assert_eq!(config.value, DnsResolver::Native);

        let config: Wrapper = toml::from_str(r#"value = "direct""#).unwrap();
        assert_eq!(config.value, DnsResolver::Direct);

        let config: Wrapper = toml::from_str(r#"value = "shuffle""#).unwrap();
        assert_eq!(config.value, DnsResolver::Shuffle);
    }
}
