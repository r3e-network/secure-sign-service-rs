// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

//! Fail-closed RPC endpoint validation: HTTPS, public DNS, disjoint pins.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Client, Url};

use crate::{clean_reason, NeoRpcClient, RpcVerificationError};

pub trait HostResolver: Send + Sync + 'static {
    fn resolve(&self, host: &str) -> Result<BTreeSet<IpAddr>, RpcVerificationError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemHostResolver;

impl HostResolver for SystemHostResolver {
    fn resolve(&self, host: &str) -> Result<BTreeSet<IpAddr>, RpcVerificationError> {
        let addrs =
            (host, 0u16)
                .to_socket_addrs()
                .map_err(|err| RpcVerificationError::DnsResolution {
                    host: host.to_owned(),
                    reason: clean_reason(&err),
                })?;
        let ips = addrs.map(|addr| addr.ip()).collect::<BTreeSet<_>>();
        if ips.is_empty() {
            return Err(RpcVerificationError::DnsResolution {
                host: host.to_owned(),
                reason: "resolver returned no addresses".to_owned(),
            });
        }
        Ok(ips)
    }
}

#[derive(Clone)]
struct PinnedHostResolver {
    inner: Arc<dyn HostResolver>,
    pins: HashMap<String, BTreeSet<IpAddr>>,
}

impl PinnedHostResolver {
    fn resolve_pinned(&self, host: &str) -> Result<BTreeSet<IpAddr>, RpcVerificationError> {
        let lower = host.to_ascii_lowercase();
        let current = resolve_public_addresses(self.inner.as_ref(), &lower)?;
        match self.pins.get(&lower) {
            Some(expected) if expected == &current => Ok(current),
            Some(_) => Err(RpcVerificationError::EndpointNotAllowed(
                "DNS resolution changed after pinning".to_owned(),
            )),
            None => Err(RpcVerificationError::EndpointNotAllowed(
                "host is not a pinned RPC endpoint".to_owned(),
            )),
        }
    }
}

impl Resolve for PinnedHostResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let this = self.clone();
        Box::pin(async move {
            this.resolve_pinned(name.as_str())
                .map(|ips| -> Addrs { Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0))) })
                .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)
        })
    }
}

#[derive(Debug)]
struct InspectedEndpoint {
    url: Url,
    host: String,
    ips: BTreeSet<IpAddr>,
}

pub fn build_clients(
    endpoints: &str,
    timeout: Duration,
    resolver: Arc<dyn HostResolver>,
) -> Result<[NeoRpcClient; 2], RpcVerificationError> {
    let urls: Vec<_> = endpoints
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect();
    if urls.len() != 2 {
        return Err(RpcVerificationError::EndpointCount);
    }

    let first = inspect_endpoint(urls[0], resolver.as_ref())?;
    let second = inspect_endpoint(urls[1], resolver.as_ref())?;
    if first.host == second.host {
        return Err(RpcVerificationError::HostsNotIndependent);
    }
    if !first.ips.is_disjoint(&second.ips) {
        return Err(RpcVerificationError::ResolutionsNotIndependent);
    }

    let dns = Arc::new(PinnedHostResolver {
        inner: resolver,
        pins: HashMap::from([
            (first.host.clone(), first.ips.clone()),
            (second.host.clone(), second.ips.clone()),
        ]),
    });
    let client = Client::builder()
        .connect_timeout(timeout)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .dns_resolver(dns)
        .user_agent("neo-os-secure-signer/1")
        .build()
        .map_err(|err| RpcVerificationError::InvalidEndpoint(clean_reason(&err)))?;

    Ok([
        NeoRpcClient {
            endpoint: first.url,
            label: first.host,
            client: client.clone(),
        },
        NeoRpcClient {
            endpoint: second.url,
            label: second.host,
            client,
        },
    ])
}

fn inspect_endpoint(
    raw: &str,
    resolver: &dyn HostResolver,
) -> Result<InspectedEndpoint, RpcVerificationError> {
    let url = Url::parse(raw)
        .map_err(|_| RpcVerificationError::InvalidEndpoint("URL is invalid".to_owned()))?;
    if url.scheme() != "https" {
        return Err(RpcVerificationError::HttpsRequired);
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(RpcVerificationError::EndpointNotAllowed(
            "userinfo, query, and fragment are forbidden".to_owned(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| RpcVerificationError::InvalidEndpoint("missing host".to_owned()))?
        .to_ascii_lowercase();
    validate_public_host(&host)?;
    let ips = resolve_public_addresses(resolver, &host)?;
    Ok(InspectedEndpoint { url, host, ips })
}

fn resolve_public_addresses(
    resolver: &dyn HostResolver,
    host: &str,
) -> Result<BTreeSet<IpAddr>, RpcVerificationError> {
    let ips = if let Ok(ip) = host.parse::<IpAddr>() {
        BTreeSet::from([ip])
    } else {
        resolver.resolve(host)?
    };
    if ips.is_empty() {
        return Err(RpcVerificationError::DnsResolution {
            host: host.to_owned(),
            reason: "resolver returned no addresses".to_owned(),
        });
    }
    for ip in &ips {
        if is_forbidden_ip(*ip) {
            return Err(RpcVerificationError::EndpointNotAllowed(format!(
                "resolved non-public address {ip}"
            )));
        }
    }
    Ok(ips)
}

pub fn validate_public_host(host: &str) -> Result<(), RpcVerificationError> {
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".local") {
        return Err(RpcVerificationError::EndpointNotAllowed(
            "local hosts are forbidden".to_owned(),
        ));
    }
    if let Ok(ip) = lower.parse::<IpAddr>() {
        if is_forbidden_ip(ip) {
            return Err(RpcVerificationError::EndpointNotAllowed(
                "private or special-use IP address".to_owned(),
            ));
        }
    }
    Ok(())
}

pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => is_forbidden_ipv4(value),
        IpAddr::V6(value) => is_forbidden_ipv6(value),
    }
}

fn is_forbidden_ipv4(value: Ipv4Addr) -> bool {
    value.is_unspecified()
        || value.is_loopback()
        || value.is_private()
        || value.is_link_local()
        || value.is_multicast()
        || value.is_broadcast()
        || value.is_documentation()
        || is_reserved_ipv4(value)
}

fn is_reserved_ipv4(value: Ipv4Addr) -> bool {
    let [a, b, c, _] = value.octets();
    a == 0
        || a >= 240
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (18..20).contains(&b))
}

fn is_forbidden_ipv6(value: Ipv6Addr) -> bool {
    if let Some(mapped) = value.to_ipv4_mapped() {
        return is_forbidden_ipv4(mapped);
    }
    value.is_unspecified()
        || value.is_loopback()
        || value.is_unique_local()
        || value.is_unicast_link_local()
        || value.is_multicast()
        || is_reserved_ipv6(value)
}

fn is_reserved_ipv6(value: Ipv6Addr) -> bool {
    let segments = value.segments();
    (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0)
}

#[cfg(test)]
pub(crate) struct MapResolver {
    pub answers: HashMap<String, BTreeSet<IpAddr>>,
}

#[cfg(test)]
impl HostResolver for MapResolver {
    fn resolve(&self, host: &str) -> Result<BTreeSet<IpAddr>, RpcVerificationError> {
        self.answers
            .get(&host.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| RpcVerificationError::DnsResolution {
                host: host.to_owned(),
                reason: "no fixture".to_owned(),
            })
    }
}

#[cfg(test)]
pub(crate) struct SequenceResolver {
    pub answers: std::sync::Mutex<HashMap<String, Vec<BTreeSet<IpAddr>>>>,
}

#[cfg(test)]
impl HostResolver for SequenceResolver {
    fn resolve(&self, host: &str) -> Result<BTreeSet<IpAddr>, RpcVerificationError> {
        let mut answers = self.answers.lock().expect("resolver fixture lock");
        let sequence = answers.get_mut(&host.to_ascii_lowercase()).ok_or_else(|| {
            RpcVerificationError::DnsResolution {
                host: host.to_owned(),
                reason: "no fixture".to_owned(),
            }
        })?;
        if sequence.is_empty() {
            return Err(RpcVerificationError::DnsResolution {
                host: host.to_owned(),
                reason: "no remaining fixture answers".to_owned(),
            });
        }
        Ok(sequence.remove(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_ssrf_addresses_are_rejected() {
        for host in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.8",
            "169.254.1.1",
            "224.0.0.1",
            "240.0.0.1",
            "0.0.0.0",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12::1",
            "ff02::1",
            "::",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                validate_public_host(host).is_err(),
                "expected {host} to be forbidden"
            );
        }
        assert!(validate_public_host("203.0.113.10").is_err());
        assert!(validate_public_host("1.1.1.1").is_ok());
        assert!(validate_public_host("2001:4860:4860::8888").is_ok());
    }

    #[test]
    fn documentation_ipv4_is_reserved_for_rpc() {
        assert!(is_forbidden_ip("203.0.113.10".parse().unwrap()));
    }

    #[test]
    fn pinned_resolver_rejects_private_rebind_and_changed_public_set() {
        use std::sync::Mutex;

        let rebind = Arc::new(SequenceResolver {
            answers: Mutex::new(HashMap::from([(
                "rpc-a.example".to_owned(),
                vec![
                    BTreeSet::from(["1.1.1.1".parse().unwrap()]),
                    BTreeSet::from(["127.0.0.1".parse().unwrap()]),
                ],
            )])),
        });
        let first = resolve_public_addresses(rebind.as_ref(), "rpc-a.example").unwrap();
        let pinned = PinnedHostResolver {
            inner: rebind,
            pins: HashMap::from([("rpc-a.example".to_owned(), first)]),
        };
        let err = pinned.resolve_pinned("rpc-a.example").unwrap_err();
        assert!(
            matches!(err, RpcVerificationError::EndpointNotAllowed(ref reason) if reason.contains("non-public")),
            "{err}"
        );

        let changed = Arc::new(SequenceResolver {
            answers: Mutex::new(HashMap::from([(
                "rpc-a.example".to_owned(),
                vec![
                    BTreeSet::from(["1.1.1.1".parse().unwrap()]),
                    BTreeSet::from(["9.9.9.9".parse().unwrap()]),
                ],
            )])),
        });
        let first = resolve_public_addresses(changed.as_ref(), "rpc-a.example").unwrap();
        let pinned = PinnedHostResolver {
            inner: changed,
            pins: HashMap::from([("rpc-a.example".to_owned(), first)]),
        };
        let err = pinned.resolve_pinned("rpc-a.example").unwrap_err();
        assert!(
            matches!(err, RpcVerificationError::EndpointNotAllowed(ref reason) if reason.contains("changed")),
            "{err}"
        );
    }

    #[test]
    fn query_userinfo_and_fragment_are_rejected_without_echoing_secrets() {
        let resolver = MapResolver {
            answers: HashMap::from([(
                "rpc-a.example".to_owned(),
                BTreeSet::from(["1.1.1.1".parse().unwrap()]),
            )]),
        };
        for raw in [
            "https://user:super-secret@rpc-a.example/path",
            "https://rpc-a.example/path?api_key=super-secret",
            "https://rpc-a.example/path#api_key=super-secret",
        ] {
            let err = inspect_endpoint(raw, &resolver).unwrap_err();
            let rendered = err.to_string();
            assert!(
                matches!(err, RpcVerificationError::EndpointNotAllowed(_)),
                "{rendered}"
            );
            assert!(
                !rendered.contains("super-secret") && !rendered.contains("api_key"),
                "{rendered}"
            );
        }
        assert!(inspect_endpoint("https://rpc-a.example/rpc", &resolver).is_ok());
    }

    #[test]
    fn parse_errors_do_not_echo_embedded_secrets() {
        let resolver = MapResolver {
            answers: HashMap::new(),
        };
        let err = inspect_endpoint("https://user:super-secret@", &resolver).unwrap_err();
        let rendered = format!("{err} {}", crate::clean_reason(&err));
        assert!(!rendered.contains("super-secret"), "{rendered}");
    }
}
