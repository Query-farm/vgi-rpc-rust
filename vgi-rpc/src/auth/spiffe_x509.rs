//! Shared strict X.509-SVID leaf validation.

use std::collections::BTreeSet;

use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

use super::spiffe_proxy::validate_spiffe_id;

pub(crate) fn x509_svid_from_der(
    der: &[u8],
    trust_domains: &BTreeSet<String>,
) -> Result<(String, String), ()> {
    let (trailing, certificate) = parse_x509_certificate(der).map_err(|_| ())?;
    if !trailing.is_empty() || !certificate.validity().is_valid() {
        return Err(());
    }
    let san = certificate
        .subject_alternative_name()
        .map_err(|_| ())?
        .ok_or(())?;
    let uris = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [id] = uris.as_slice() else {
        return Err(());
    };
    let trust_domain = validate_spiffe_id(id, trust_domains)
        .map_err(|_| ())?
        .to_owned();
    if certificate.subject().iter_attributes().next().is_none() && !san.critical {
        return Err(());
    }
    let basic = certificate.basic_constraints().map_err(|_| ())?.ok_or(())?;
    if basic.value.ca {
        return Err(());
    }
    let usage = certificate.key_usage().map_err(|_| ())?.ok_or(())?;
    if !usage.critical
        || !usage.value.digital_signature()
        || usage.value.key_cert_sign()
        || usage.value.crl_sign()
    {
        return Err(());
    }
    if let Some(extended) = certificate.extended_key_usage().map_err(|_| ())? {
        if !extended.value.client_auth || !extended.value.server_auth {
            return Err(());
        }
    }
    Ok(((*id).to_owned(), trust_domain))
}
