//! Top-level address validation for the browser host.
//!
//! This is not a network firewall: WebView subresources and DNS resolution are
//! controlled by the platform engine and operating system. See BROWSER_RUNTIME.md.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NavigationError {
    EmptyAddress,
    AddressTooLong,
    InvalidAddress,
    UnsupportedScheme,
    EmbeddedCredentials,
    LocalHost,
    LocalAddress,
}

impl std::fmt::Display for NavigationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::EmptyAddress => "Enter an address or search query.",
            Self::AddressTooLong => "Addresses are limited to 2,048 bytes.",
            Self::InvalidAddress => "The address is not a valid URL.",
            Self::UnsupportedScheme => "Only HTTP and HTTPS pages can be opened.",
            Self::EmbeddedCredentials => "Credentials are not allowed in page URLs.",
            Self::LocalHost => "Local and internal hostnames are blocked by the default navigation policy.",
            Self::LocalAddress => "Private, loopback, link-local, and reserved IP addresses are blocked by the default navigation policy.",
        };
        f.write_str(message)
    }
}

impl std::error::Error for NavigationError {}

/// Convert an address-bar value to an HTTP(S) URL and apply top-level policy.
pub fn resolve_address(input: &str) -> Result<Url, NavigationError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(NavigationError::EmptyAddress);
    }
    if input.len() > 2048 {
        return Err(NavigationError::AddressTooLong);
    }

    let candidate = if input.chars().any(char::is_whitespace) {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("q", input)
            .finish();
        format!("https://duckduckgo.com/?{query}")
    } else if input.contains("://") {
        input.to_owned()
    } else {
        format!("https://{input}")
    };

    let url = Url::parse(&candidate).map_err(|_| NavigationError::InvalidAddress)?;
    validate_navigation(&url)?;
    Ok(url)
}

/// Validate a top-level navigation request originating from the address bar,
/// a link, redirect, or window-open request.
pub fn validate_navigation(raw: &str) -> Result<Url, NavigationError> {
    if raw.len() > 2048 {
        return Err(NavigationError::AddressTooLong);
    }
    let url = Url::parse(raw).map_err(|_| NavigationError::InvalidAddress)?;
    validate_url(&url)?;
    Ok(url)
}

fn validate_url(url: &Url) -> Result<(), NavigationError> {
    match url.scheme() {
        "http" | "https" => {}
        _ => return Err(NavigationError::UnsupportedScheme),
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(NavigationError::EmbeddedCredentials);
    }

    let host = url.host().ok_or(NavigationError::InvalidAddress)?;
    match host {
        url::Host::Ipv4(address) if is_blocked_ipv4(address) => {
            return Err(NavigationError::LocalAddress);
        }
        url::Host::Ipv6(address) if is_blocked_ip(IpAddr::V6(address)) => {
            return Err(NavigationError::LocalAddress);
        }
        url::Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            if domain == "localhost"
                || domain.ends_with(".localhost")
                || domain.ends_with(".local")
                || domain.ends_with(".internal")
                || domain == "metadata.google.internal"
                || domain == "instance-data.ec2.internal"
            {
                return Err(NavigationError::LocalHost);
            }
        }
        _ => {}
    }

    Ok(())
}

fn is_blocked_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_blocked_ipv4(address),
        IpAddr::V6(address) => {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_multicast()
                || address.segments()[0] == 0x2001 && address.segments()[1] == 0x0db8
                || address.to_ipv4_mapped().is_some_and(is_blocked_ipv4)
        }
    }
}

fn is_blocked_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_unspecified()
        || address.is_multicast()
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 240
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_public_http_and_https_addresses() {
        assert_eq!(resolve_address("example.com").unwrap().as_str(), "https://example.com/");
        assert_eq!(resolve_address("http://example.com").unwrap().scheme(), "http");
        assert!(validate_navigation("https://www.rust-lang.org/").is_ok());
    }

    #[test]
    fn converts_search_terms_to_search_url() {
        let url = resolve_address("Rust WebView engine").unwrap();
        assert_eq!(url.host_str(), Some("duckduckgo.com"));
        assert!(url.query().unwrap().contains("Rust+WebView+engine"));
    }

    #[test]
    fn rejects_non_web_schemes_and_credentials() {
        assert_eq!(validate_navigation("javascript:alert(1)"), Err(NavigationError::UnsupportedScheme));
        assert_eq!(validate_navigation("file:///etc/passwd"), Err(NavigationError::UnsupportedScheme));
        assert_eq!(validate_navigation("https://user:pass@example.com"), Err(NavigationError::EmbeddedCredentials));
    }

    #[test]
    fn rejects_obvious_local_and_reserved_targets() {
        for url in [
            "http://localhost/",
            "http://service.local/",
            "http://10.0.0.7/",
            "http://127.0.0.1/",
            "http://169.254.169.254/",
            "http://192.0.2.1/",
            "http://203.0.113.1/",
            "http://[::1]/",
            "http://[2001:db8::1]/",
            "http://[fd00::1]/",
        ] {
            assert!(validate_navigation(url).is_err(), "expected {url} to be blocked");
        }
    }

    #[test]
    fn rejects_empty_and_malformed_inputs() {
        assert_eq!(resolve_address("  "), Err(NavigationError::EmptyAddress));
        assert_eq!(resolve_address("x".repeat(2049).as_str()), Err(NavigationError::AddressTooLong));
        assert_eq!(resolve_address("https://"), Err(NavigationError::InvalidAddress));
    }
}
