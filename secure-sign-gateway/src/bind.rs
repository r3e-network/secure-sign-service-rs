// Copyright @ 2025 - Present, R3E Network
// All Rights Reserved

use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const DEFAULT_WIREGUARD_LISTEN: &str = "10.78.0.1:9991";
pub const DEFAULT_WIREGUARD_CIDR: &str = "10.78.0.0/24";
const MIN_PRIVATE_IPV4_PREFIX: u8 = 16;
const MIN_PRIVATE_IPV6_PREFIX: u8 = 64;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BindError {
    InvalidCidr(String),
    NotAllowed(SocketAddr),
    WildcardDenied,
    DangerousCidr(String),
}

impl Display for BindError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCidr(reason) => write!(f, "bind CIDR is invalid: {reason}"),
            Self::NotAllowed(addr) => write!(
                f,
                "listen address {addr} is not the WireGuard parent or an allowlisted CIDR"
            ),
            Self::WildcardDenied => write!(
                f,
                "wildcard bind (0.0.0.0/:: / 0.0.0.0/0 / ::/0) requires --allow-wildcard-bind and an external firewall"
            ),
            Self::DangerousCidr(cidr) => write!(
                f,
                "public, global, or wide bind {cidr} requires --allow-wildcard-bind and an external firewall"
            ),
        }
    }
}

impl Display for Cidr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

impl std::error::Error for BindError {}

impl Cidr {
    pub fn parse(raw: &str) -> Result<Self, BindError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(BindError::InvalidCidr("empty CIDR".to_owned()));
        }
        let (addr, prefix) = match trimmed.split_once('/') {
            Some((addr, prefix)) => {
                let addr = addr
                    .parse::<IpAddr>()
                    .map_err(|err| BindError::InvalidCidr(err.to_string()))?;
                let prefix = prefix
                    .parse::<u8>()
                    .map_err(|err| BindError::InvalidCidr(err.to_string()))?;
                (addr, prefix)
            }
            None => {
                let addr = trimmed
                    .parse::<IpAddr>()
                    .map_err(|err| BindError::InvalidCidr(err.to_string()))?;
                let prefix = if addr.is_ipv4() { 32 } else { 128 };
                (addr, prefix)
            }
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(BindError::InvalidCidr(format!(
                "prefix {prefix} exceeds {max}"
            )));
        }
        Ok(Self {
            network: addr,
            prefix,
        })
    }

    pub fn contains(self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(addr)) => {
                ipv4_prefix(network, self.prefix) == ipv4_prefix(addr, self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(addr)) => {
                ipv6_prefix(network, self.prefix) == ipv6_prefix(addr, self.prefix)
            }
            _ => false,
        }
    }

    pub fn is_unspecified_wildcard(self) -> bool {
        match self.network {
            IpAddr::V4(addr) => addr.is_unspecified() && self.prefix == 0,
            IpAddr::V6(addr) => addr.is_unspecified() && self.prefix == 0,
        }
    }

    pub fn is_wide(self) -> bool {
        match self.network {
            IpAddr::V4(_) => self.prefix < MIN_PRIVATE_IPV4_PREFIX,
            IpAddr::V6(_) => self.prefix < MIN_PRIVATE_IPV6_PREFIX,
        }
    }

    pub fn is_private_or_local(self) -> bool {
        ip_is_private_or_local(self.network)
    }

    pub fn is_dangerous(self) -> bool {
        self.is_unspecified_wildcard() || self.is_wide() || !self.is_private_or_local()
    }
}

pub fn default_wireguard_cidr() -> Cidr {
    Cidr::parse(DEFAULT_WIREGUARD_CIDR).expect("compiled WireGuard CIDR")
}

pub const WILDCARD_BIND_WARNING: &str =
    "WARNING: wildcard listen is enabled; an external host firewall must restrict access before this process is reachable";

pub fn validate_listen_address(
    listen: SocketAddr,
    extra_cidrs: &[Cidr],
    allow_wildcard_bind: bool,
) -> Result<bool, BindError> {
    let listen_unspecified = listen.ip().is_unspecified();
    let extra_wildcard = extra_cidrs
        .iter()
        .any(|cidr| cidr.is_unspecified_wildcard());
    if (listen_unspecified || extra_wildcard) && !allow_wildcard_bind {
        return Err(BindError::WildcardDenied);
    }
    if !allow_wildcard_bind {
        if let Some(cidr) = extra_cidrs.iter().find(|cidr| cidr.is_dangerous()) {
            return Err(BindError::DangerousCidr(cidr.to_string()));
        }
        if !listen_unspecified && !ip_is_private_or_local(listen.ip()) {
            return Err(BindError::DangerousCidr(format!("{}/host", listen.ip())));
        }
    }
    if listen_unspecified {
        return Ok(true);
    }
    if default_wireguard_cidr().contains(listen.ip())
        || extra_cidrs
            .iter()
            .filter(|cidr| !cidr.is_unspecified_wildcard() || allow_wildcard_bind)
            .any(|cidr| cidr.contains(listen.ip()))
    {
        Ok(extra_wildcard || extra_cidrs.iter().any(|cidr| cidr.is_dangerous()))
    } else {
        Err(BindError::NotAllowed(listen))
    }
}

fn ip_is_private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => addr.is_private() || addr.is_loopback() || addr.is_link_local(),
        IpAddr::V6(addr) => {
            addr.is_loopback()
                || ipv6_is_unique_local(addr)
                || (addr.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn ipv6_is_unique_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

pub fn parse_bind_cidrs(raw: &[String]) -> Result<Vec<Cidr>, BindError> {
    raw.iter()
        .filter(|value| !value.trim().is_empty())
        .map(|value| Cidr::parse(value))
        .collect()
}

fn ipv4_prefix(addr: Ipv4Addr, prefix: u8) -> u32 {
    let value = u32::from(addr);
    if prefix == 0 {
        0
    } else {
        value & (!0u32 << (32 - prefix))
    }
}

fn ipv6_prefix(addr: Ipv6Addr, prefix: u8) -> u128 {
    let value = u128::from(addr);
    if prefix == 0 {
        0
    } else {
        value & (!0u128 << (128 - prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_wireguard_listen_is_allowed_without_extra_cidrs() {
        let listen = DEFAULT_WIREGUARD_LISTEN.parse().unwrap();
        assert!(!validate_listen_address(listen, &[], false).unwrap());
        assert!(validate_listen_address("10.78.0.20:9991".parse().unwrap(), &[], false).is_ok());
    }

    #[test]
    fn unspecified_and_foreign_binds_fail_closed() {
        assert!(matches!(
            validate_listen_address("0.0.0.0:9991".parse().unwrap(), &[], false),
            Err(BindError::WildcardDenied)
        ));
        assert!(matches!(
            validate_listen_address("[::]:9991".parse().unwrap(), &[], false),
            Err(BindError::WildcardDenied)
        ));
        assert!(validate_listen_address("192.168.1.10:9991".parse().unwrap(), &[], false).is_err());
        assert!(validate_listen_address("127.0.0.1:9991".parse().unwrap(), &[], false).is_err());
    }

    #[test]
    fn explicit_cidr_can_allow_an_additional_bind() {
        let cidrs = parse_bind_cidrs(&["192.168.10.0/24".to_owned()]).unwrap();
        assert!(
            validate_listen_address("192.168.10.7:9991".parse().unwrap(), &cidrs, false).is_ok()
        );
        assert!(
            validate_listen_address("192.168.11.7:9991".parse().unwrap(), &cidrs, false).is_err()
        );
        assert!(matches!(
            validate_listen_address("0.0.0.0:9991".parse().unwrap(), &cidrs, false),
            Err(BindError::WildcardDenied)
        ));
    }

    #[test]
    fn wildcard_cidr_alone_cannot_open_all_interfaces() {
        let cidrs = parse_bind_cidrs(&["0.0.0.0/0".to_owned()]).unwrap();
        assert!(matches!(
            validate_listen_address("0.0.0.0:9991".parse().unwrap(), &cidrs, false),
            Err(BindError::WildcardDenied)
        ));
        assert!(matches!(
            validate_listen_address("203.0.113.9:9991".parse().unwrap(), &cidrs, false),
            Err(BindError::WildcardDenied)
        ));
        assert!(validate_listen_address("0.0.0.0:9991".parse().unwrap(), &cidrs, true).unwrap());
        assert!(
            validate_listen_address("203.0.113.9:9991".parse().unwrap(), &cidrs, true).unwrap()
        );
    }

    #[test]
    fn public_and_wide_cidrs_require_the_danger_switch() {
        for raw in [
            "0.0.0.0/1",
            "1.0.0.0/8",
            "8.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "2000::/3",
            "::/1",
            "2001:db8::/32",
        ] {
            let cidrs = parse_bind_cidrs(&[raw.to_owned()]).unwrap();
            assert!(
                matches!(
                    validate_listen_address("10.78.0.1:9991".parse().unwrap(), &cidrs, false),
                    Err(BindError::DangerousCidr(_))
                ),
                "{raw} must require the danger switch"
            );
        }

        let public = parse_bind_cidrs(&["203.0.113.0/24".to_owned()]).unwrap();
        assert!(matches!(
            validate_listen_address("203.0.113.9:9991".parse().unwrap(), &public, false),
            Err(BindError::DangerousCidr(_))
        ));
        assert!(
            validate_listen_address("203.0.113.9:9991".parse().unwrap(), &public, true).unwrap()
        );

        let private_24 = parse_bind_cidrs(&["192.168.10.0/24".to_owned()]).unwrap();
        assert!(
            validate_listen_address("192.168.10.7:9991".parse().unwrap(), &private_24, false)
                .is_ok()
        );
        let ula = parse_bind_cidrs(&["fd12:3456:789a::/64".to_owned()]).unwrap();
        assert!(
            validate_listen_address("[fd12:3456:789a::1]:9991".parse().unwrap(), &ula, false)
                .is_ok()
        );
    }
}
