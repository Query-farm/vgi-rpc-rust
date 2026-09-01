//! Strict, bounded PROXY protocol v2 parsing.

use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];
const FIXED_BYTES: usize = 16;
pub const DEFAULT_MAX_PROXY_V2_BYTES: usize = 536;
/// Private-use PROXY-v2 TLV carrying a bridge-authenticated Iroh EndpointId.
pub const VGI_IROH_ENDPOINT_TLV: u8 = 0xe0;

const VGI_IROH_ENDPOINT_VERSION: u8 = 1;
const VGI_IROH_ENDPOINT_VALUE_BYTES: usize = 33;

/// Asserted TCP endpoints from one trusted PROXY v2 preamble.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyProtocolV2Address {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

/// Explicitly enabled identity extensions. The default preserves the strict
/// TCP/IPv4-or-IPv6 parser contract.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProxyProtocolV2ParseOptions {
    pub allow_iroh_identity: bool,
}

/// Parsed trusted preamble before a listener decides how to use its evidence.
/// Iroh's non-IP identity has no synthetic source or destination address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedProxyProtocolV2 {
    pub address: Option<ProxyProtocolV2Address>,
    pub iroh_endpoint_id: Option<[u8; 32]>,
}

/// Read exactly one bounded PROXY v2 preamble. Following VGI bytes remain in
/// `reader` because the function never reads beyond the declared length.
pub fn read_proxy_protocol_v2<R: Read>(
    reader: &mut R,
    maximum_bytes: usize,
) -> io::Result<ProxyProtocolV2Address> {
    read_proxy_protocol_v2_with_options(reader, maximum_bytes, Default::default())?
        .address
        .ok_or_else(|| invalid("PROXY v2 requires TCP over IPv4 or IPv6"))
}

/// Read one bounded preamble with explicitly enabled identity extensions.
pub fn read_proxy_protocol_v2_with_options<R: Read>(
    reader: &mut R,
    maximum_bytes: usize,
    options: ProxyProtocolV2ParseOptions,
) -> io::Result<ParsedProxyProtocolV2> {
    let maximum_bytes = maximum_bytes_or_default(maximum_bytes)?;
    let mut fixed = [0u8; FIXED_BYTES];
    reader.read_exact(&mut fixed).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("truncated PROXY v2 fixed preamble: {error}"),
        )
    })?;
    let total = FIXED_BYTES + usize::from(u16::from_be_bytes([fixed[14], fixed[15]]));
    if total > maximum_bytes {
        return Err(invalid("PROXY v2 preamble exceeds configured limit"));
    }
    let mut preamble = vec![0; total];
    preamble[..FIXED_BYTES].copy_from_slice(&fixed);
    reader
        .read_exact(&mut preamble[FIXED_BYTES..])
        .map_err(|error| {
            io::Error::new(error.kind(), format!("truncated PROXY v2 body: {error}"))
        })?;
    parse_proxy_protocol_v2_with_options(&preamble, maximum_bytes, options)
}

/// Parse one exact preamble. Only PROXY with TCP over IPv4/IPv6 is accepted;
/// LOCAL, UNSPEC, UDP, Unix-family and malformed TLVs fail closed.
pub fn parse_proxy_protocol_v2(
    preamble: &[u8],
    maximum_bytes: usize,
) -> io::Result<ProxyProtocolV2Address> {
    parse_proxy_protocol_v2_with_options(preamble, maximum_bytes, Default::default())?
        .address
        .ok_or_else(|| invalid("PROXY v2 requires TCP over IPv4 or IPv6"))
}

/// Parse one exact preamble with explicitly enabled identity extensions.
/// Iroh forwarding permits only PROXY/UNSPEC carrying exactly one fixed,
/// versioned EndpointId identity TLV. Other bounded, structurally valid TLVs
/// remain opaque extensions.
pub fn parse_proxy_protocol_v2_with_options(
    preamble: &[u8],
    maximum_bytes: usize,
    options: ProxyProtocolV2ParseOptions,
) -> io::Result<ParsedProxyProtocolV2> {
    let maximum_bytes = maximum_bytes_or_default(maximum_bytes)?;
    if preamble.len() < FIXED_BYTES {
        return Err(invalid("truncated PROXY v2 fixed preamble"));
    }
    if preamble.len() > maximum_bytes {
        return Err(invalid("PROXY v2 preamble exceeds configured limit"));
    }
    if preamble[..12] != SIGNATURE {
        return Err(invalid("missing PROXY v2 signature"));
    }
    if preamble[12] >> 4 != 2 {
        return Err(invalid("unsupported PROXY protocol version"));
    }
    if preamble[12] & 0x0f != 1 {
        return Err(invalid("PROXY v2 LOCAL command is not accepted"));
    }
    let expected = FIXED_BYTES + usize::from(u16::from_be_bytes([preamble[14], preamble[15]]));
    if preamble.len() != expected {
        return Err(invalid("truncated or overlong PROXY v2 preamble"));
    }
    let body = &preamble[FIXED_BYTES..];
    let (address, address_bytes) = match preamble[13] {
        0x00 if options.allow_iroh_identity => (None, 0),
        0x11 => {
            if body.len() < 12 {
                return Err(invalid("truncated PROXY v2 TCP/IPv4 address block"));
            }
            let source = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(body[0], body[1], body[2], body[3])),
                u16::from_be_bytes([body[8], body[9]]),
            );
            let destination = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(body[4], body[5], body[6], body[7])),
                u16::from_be_bytes([body[10], body[11]]),
            );
            (
                Some(ProxyProtocolV2Address {
                    source,
                    destination,
                }),
                12,
            )
        }
        0x21 => {
            if body.len() < 36 {
                return Err(invalid("truncated PROXY v2 TCP/IPv6 address block"));
            }
            let mut source = [0u8; 16];
            let mut destination = [0u8; 16];
            source.copy_from_slice(&body[..16]);
            destination.copy_from_slice(&body[16..32]);
            let source = SocketAddr::new(
                normalize_ip(IpAddr::V6(Ipv6Addr::from(source))),
                u16::from_be_bytes([body[32], body[33]]),
            );
            let destination = SocketAddr::new(
                normalize_ip(IpAddr::V6(Ipv6Addr::from(destination))),
                u16::from_be_bytes([body[34], body[35]]),
            );
            (
                Some(ProxyProtocolV2Address {
                    source,
                    destination,
                }),
                36,
            )
        }
        _ => return Err(invalid("PROXY v2 requires TCP over IPv4 or IPv6")),
    };
    let mut iroh_endpoint_id = None;
    let mut offset = address_bytes;
    while offset < body.len() {
        if body.len() - offset < 3 {
            return Err(invalid("truncated PROXY v2 TLV header"));
        }
        let tlv_type = body[offset];
        let length = usize::from(u16::from_be_bytes([body[offset + 1], body[offset + 2]]));
        offset += 3;
        if length > body.len() - offset {
            return Err(invalid("truncated PROXY v2 TLV value"));
        }
        let value = &body[offset..offset + length];
        if tlv_type == VGI_IROH_ENDPOINT_TLV && options.allow_iroh_identity {
            if iroh_endpoint_id.is_some() {
                return Err(invalid("duplicate VGI Iroh identity TLV"));
            }
            if value.len() != VGI_IROH_ENDPOINT_VALUE_BYTES
                || value.first() != Some(&VGI_IROH_ENDPOINT_VERSION)
            {
                return Err(invalid("invalid VGI Iroh identity TLV"));
            }
            let mut endpoint = [0u8; 32];
            endpoint.copy_from_slice(&value[1..]);
            iroh_endpoint_id = Some(endpoint);
        }
        offset += length;
    }
    if preamble[13] == 0x00 && iroh_endpoint_id.is_none() {
        return Err(invalid("PROXY/UNSPEC requires one VGI Iroh identity TLV"));
    }
    if iroh_endpoint_id.is_some() && preamble[13] != 0x00 {
        return Err(invalid("VGI Iroh identity requires PROXY/UNSPEC"));
    }
    Ok(ParsedProxyProtocolV2 {
        address,
        iroh_endpoint_id,
    })
}

fn maximum_bytes_or_default(maximum_bytes: usize) -> io::Result<usize> {
    let maximum_bytes = if maximum_bytes == 0 {
        DEFAULT_MAX_PROXY_V2_BYTES
    } else {
        maximum_bytes
    };
    if maximum_bytes < FIXED_BYTES {
        Err(invalid("maximum PROXY v2 bytes must be at least 16"))
    } else {
        Ok(maximum_bytes)
    }
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ipv4() -> Vec<u8> {
        let mut value = SIGNATURE.to_vec();
        value.extend_from_slice(&[0x21, 0x11, 0, 12]);
        value.extend_from_slice(&[192, 0, 2, 7, 198, 51, 100, 9]);
        value.extend_from_slice(&12345u16.to_be_bytes());
        value.extend_from_slice(&9400u16.to_be_bytes());
        value
    }

    fn iroh(version: u8, endpoint_bytes: usize) -> Vec<u8> {
        let mut body = vec![
            VGI_IROH_ENDPOINT_TLV,
            0,
            u8::try_from(1 + endpoint_bytes).unwrap(),
            version,
        ];
        body.extend((0..endpoint_bytes).map(|value| u8::try_from(value).unwrap()));
        let mut value = SIGNATURE.to_vec();
        value.extend_from_slice(&[0x21, 0x00]);
        value.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        value.extend_from_slice(&body);
        value
    }

    #[test]
    fn parses_tcp_and_preserves_following_bytes() {
        let mut wire = ipv4();
        wire.push(0xaa);
        let mut cursor = Cursor::new(wire);
        let address = read_proxy_protocol_v2(&mut cursor, 536).unwrap();
        assert_eq!(address.source, "192.0.2.7:12345".parse().unwrap());
        let mut following = [0];
        cursor.read_exact(&mut following).unwrap();
        assert_eq!(following, [0xaa]);
    }

    #[test]
    fn parses_mapped_ipv6_as_ipv4_and_bounded_tlv() {
        let mapped = Ipv4Addr::new(192, 0, 2, 7).to_ipv6_mapped().octets();
        let destination = Ipv6Addr::LOCALHOST.octets();
        let mut value = SIGNATURE.to_vec();
        value.extend_from_slice(&[0x21, 0x21, 0, 40]);
        value.extend_from_slice(&mapped);
        value.extend_from_slice(&destination);
        value.extend_from_slice(&12345u16.to_be_bytes());
        value.extend_from_slice(&9400u16.to_be_bytes());
        value.extend_from_slice(&[0xee, 0, 1, 0xff]);
        let address = parse_proxy_protocol_v2(&value, 536).unwrap();
        assert!(address.source.is_ipv4());
    }

    #[test]
    fn rejects_unsafe_forms_and_malformed_tlvs() {
        for (command, family) in [(0x20, 0x11), (0x21, 0x00), (0x21, 0x12)] {
            let mut value = ipv4();
            value[12] = command;
            value[13] = family;
            assert!(parse_proxy_protocol_v2(&value, 536).is_err());
        }
        let mut tlv = ipv4();
        tlv[15] = 15;
        tlv.extend_from_slice(&[1, 0, 2]);
        assert!(parse_proxy_protocol_v2(&tlv, 536).is_err());
    }

    #[test]
    fn iroh_identity_requires_explicit_unspec_opt_in_and_matches_canonical_vector() {
        let preamble = iroh(1, 32);
        assert!(parse_proxy_protocol_v2(&preamble, 536).is_err());
        let parsed = parse_proxy_protocol_v2_with_options(
            &preamble,
            536,
            ProxyProtocolV2ParseOptions {
                allow_iroh_identity: true,
            },
        )
        .unwrap();
        assert_eq!(parsed.address, None);
        assert_eq!(
            parsed.iroh_endpoint_id,
            Some(std::array::from_fn(|i| i as u8))
        );

        let mut with_extension = preamble;
        with_extension[14..16].copy_from_slice(&39u16.to_be_bytes());
        with_extension.extend_from_slice(&[0x42, 0x00, 0x00]);
        assert_eq!(
            parse_proxy_protocol_v2_with_options(
                &with_extension,
                536,
                ProxyProtocolV2ParseOptions {
                    allow_iroh_identity: true,
                },
            )
            .unwrap()
            .iroh_endpoint_id,
            Some(std::array::from_fn(|i| i as u8))
        );
    }

    #[test]
    fn iroh_reader_preserves_following_vgi_bytes() {
        let mut wire = iroh(1, 32);
        wire.extend_from_slice(b"VGI");
        let mut cursor = Cursor::new(wire);
        let parsed = read_proxy_protocol_v2_with_options(
            &mut cursor,
            536,
            ProxyProtocolV2ParseOptions {
                allow_iroh_identity: true,
            },
        )
        .unwrap();
        assert!(parsed.iroh_endpoint_id.is_some());
        let mut following = [0; 3];
        cursor.read_exact(&mut following).unwrap();
        assert_eq!(&following, b"VGI");
    }

    #[test]
    fn rejects_ambiguous_or_malformed_iroh_identity() {
        let enabled = ProxyProtocolV2ParseOptions {
            allow_iroh_identity: true,
        };
        let mut missing = SIGNATURE.to_vec();
        missing.extend_from_slice(&[0x21, 0x00, 0, 0]);
        assert!(parse_proxy_protocol_v2_with_options(&missing, 536, enabled).is_err());
        assert!(parse_proxy_protocol_v2_with_options(&iroh(2, 32), 536, enabled).is_err());
        assert!(parse_proxy_protocol_v2_with_options(&iroh(1, 31), 536, enabled).is_err());

        let mut duplicate = iroh(1, 32);
        let second = duplicate[16..].to_vec();
        duplicate[14..16].copy_from_slice(&72u16.to_be_bytes());
        duplicate.extend_from_slice(&second);
        assert!(parse_proxy_protocol_v2_with_options(&duplicate, 536, enabled).is_err());

        let mut ip_identity = ipv4();
        ip_identity[14..16].copy_from_slice(&48u16.to_be_bytes());
        ip_identity.extend_from_slice(&iroh(1, 32)[16..]);
        assert!(parse_proxy_protocol_v2_with_options(&ip_identity, 536, enabled).is_err());
    }

    #[test]
    fn ordinary_parser_never_promotes_iroh_tlv_on_an_ip_preamble() {
        let mut value = ipv4();
        value[14..16].copy_from_slice(&48u16.to_be_bytes());
        value.extend_from_slice(&iroh(1, 32)[16..]);
        assert_eq!(
            parse_proxy_protocol_v2(&value, 536).unwrap().source,
            "192.0.2.7:12345".parse().unwrap()
        );
    }
}
