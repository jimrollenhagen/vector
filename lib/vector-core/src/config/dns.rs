use vector_config::configurable_component;

/// DNS resolver configuration.
///
/// Controls how Vector resolves DNS names when connecting to endpoints.
#[configurable_component]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DnsResolver {
    /// Use the system's native DNS resolution via `getaddrinfo`.
    ///
    /// This is the default mode and respects the system's full DNS configuration,
    /// including `/etc/hosts`, `nsswitch.conf`, and other OS-level settings.
    #[default]
    Native,

    /// Use direct DNS queries via hickory-resolver, returning addresses in server order.
    ///
    /// This mode bypasses the system resolver and queries DNS servers directly
    /// (configured from `/etc/resolv.conf`). All resolved addresses are returned
    /// in the order provided by the DNS server. Does not respect `/etc/hosts`.
    Direct,

    /// Use direct DNS queries via hickory-resolver, returning addresses in random order.
    ///
    /// Same as `direct`, but shuffles the resolved addresses randomly. This provides
    /// client-side load balancing when connecting to services with multiple IP addresses.
    Shuffle,
}
