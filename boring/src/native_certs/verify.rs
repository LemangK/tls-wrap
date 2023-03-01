#![allow(dead_code)]
use boring::nid;
use boring::stack::StackRef;
use boring::x509::{GeneralName, X509NameRef, X509Ref};
use std::net::IpAddr;

/// Validates that the certificate matches the provided fully qualified domain
/// name.
pub fn verify_hostname(domain: &str, cert: &X509Ref) -> bool {
    match cert.subject_alt_names() {
        Some(names) => verify_subject_alt_names(domain, &names),
        None => verify_subject_name(domain, &cert.subject_name()),
    }
}

fn verify_subject_alt_names(domain: &str, names: &StackRef<GeneralName>) -> bool {
    let ip = domain.parse();

    for name in names {
        match ip {
            Ok(ip) => {
                if let Some(actual) = name.ipaddress() {
                    if matches_ip(&ip, actual) {
                        return true;
                    }
                }
            }
            Err(_) => {
                if let Some(pattern) = name.dnsname() {
                    if matches_dns(pattern, domain, false) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

fn verify_subject_name(domain: &str, subject_name: &X509NameRef) -> bool {
    if let Some(pattern) = subject_name.entries_by_nid(nid::Nid::COMMONNAME).next() {
        let pattern = match std::str::from_utf8(pattern.data().as_slice()) {
            Ok(pattern) => pattern,
            Err(_) => return false,
        };

        // Unlike with SANs, IP addresses in the subject name don't have a
        // different encoding. We need to pass this down to matches_dns to
        // disallow wildcard matches with bogus patterns like *.0.0.1
        let is_ip = domain.parse::<IpAddr>().is_ok();

        if matches_dns(&pattern, domain, is_ip) {
            return true;
        }
    }

    false
}

fn matches_dns(mut pattern: &str, mut hostname: &str, is_ip: bool) -> bool {
    // first strip trailing . off of pattern and hostname to normalize
    if pattern.ends_with('.') {
        pattern = &pattern[..pattern.len() - 1];
    }
    if hostname.ends_with('.') {
        hostname = &hostname[..hostname.len() - 1];
    }

    matches_wildcard(pattern, hostname, is_ip).unwrap_or_else(|| pattern == hostname)
}

fn matches_wildcard(pattern: &str, hostname: &str, is_ip: bool) -> Option<bool> {
    // IP addresses and internationalized domains can't involved in wildcards
    if is_ip || pattern.starts_with("xn--") {
        return None;
    }

    let wildcard_location = match pattern.find('*') {
        Some(l) => l,
        None => return None,
    };

    let mut dot_idxs = pattern.match_indices('.').map(|(l, _)| l);
    let wildcard_end = match dot_idxs.next() {
        Some(l) => l,
        None => return None,
    };

    // Never match wildcards if the pattern has less than 2 '.'s (no *.com)
    //
    // This is a bit dubious, as it doesn't disallow other TLDs like *.co.uk.
    // Chrome has a black- and white-list for this, but Firefox (via NSS) does
    // the same thing we do here.
    //
    // The Public Suffix (https://www.publicsuffix.org/) list could
    // potentically be used here, but it's both huge and updated frequently
    // enough that management would be a PITA.
    if dot_idxs.next().is_none() {
        return None;
    }

    // Wildcards can only be in the first component
    if wildcard_location > wildcard_end {
        return None;
    }

    let hostname_label_end = match hostname.find('.') {
        Some(l) => l,
        None => return None,
    };

    // check that the non-wildcard parts are identical
    if pattern[wildcard_end..] != hostname[hostname_label_end..] {
        return Some(false);
    }

    let wildcard_prefix = &pattern[..wildcard_location];
    let wildcard_suffix = &pattern[wildcard_location + 1..wildcard_end];

    let hostname_label = &hostname[..hostname_label_end];

    // check the prefix of the first label
    if !hostname_label.starts_with(wildcard_prefix) {
        return Some(false);
    }

    // and the suffix
    if !hostname_label[wildcard_prefix.len()..].ends_with(wildcard_suffix) {
        return Some(false);
    }

    Some(true)
}

fn matches_ip(expected: &IpAddr, actual: &[u8]) -> bool {
    match (expected, actual.len()) {
        (&IpAddr::V4(ref addr), 4) => actual == addr.octets(),
        (&IpAddr::V6(ref addr), 16) => {
            let segments = [
                ((actual[0] as u16) << 8) | actual[1] as u16,
                ((actual[2] as u16) << 8) | actual[3] as u16,
                ((actual[4] as u16) << 8) | actual[5] as u16,
                ((actual[6] as u16) << 8) | actual[7] as u16,
                ((actual[8] as u16) << 8) | actual[9] as u16,
                ((actual[10] as u16) << 8) | actual[11] as u16,
                ((actual[12] as u16) << 8) | actual[13] as u16,
                ((actual[14] as u16) << 8) | actual[15] as u16,
            ];
            segments == addr.segments()
        }
        _ => false,
    }
}
