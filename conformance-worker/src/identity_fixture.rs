//! Identity deployment modes for the conformance worker.
//!
//! The fixed policy itself lives in [`vgi_rpc::conformance_identity`], shared
//! with every VGI SDK fixture worker built on this crate.

pub use vgi_rpc::conformance_identity::*;
use vgi_rpc::token_identity::IdentityImpl;

/// Which of the two hooks a fixture worker configures.
///
/// The narrowing is the property: a method whose hook the deployment did not
/// configure is not hosted at all -- absent beats routed-and-refusing -- and
/// the `protocol_hash` narrows with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityMode {
    /// No hook, so no binding, so the protocol is not hosted at all. What the
    /// plain conformance worker is, and what the group asserts against it.
    Off,
    /// Resolve and mint: both methods, the both-methods digest.
    Both,
    /// Resolve only: one method, the one-method digest.
    IntrospectOnly,
    /// The grant worker (IDENTITY_CONFORMANCE_FIXTURE.md §10): the resolver,
    /// the fixture grant keys and no mint hook -- the framework mints sealed
    /// grants and accepts them, and `resolve_token`'s credentials, as bearers.
    Grants,
}

impl IdentityMode {
    /// Parse the `--identity {off,both,introspect-only,grants}` argument.
    pub fn from_args(args: &[String]) -> Self {
        match args
            .iter()
            .position(|a| a == "--identity")
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
        {
            None | Some("off") => Self::Off,
            Some("both") => Self::Both,
            Some("introspect-only") => Self::IntrospectOnly,
            Some("grants") => Self::Grants,
            Some(other) => {
                eprintln!(
                    "[vgi-rpc] --identity must be one of off, both, introspect-only, grants; got {other:?}"
                );
                std::process::exit(2);
            }
        }
    }

    /// Build the implementation this mode configures, or `None` for `off`.
    pub fn build(self) -> Option<IdentityImpl> {
        if self == Self::Off {
            return None;
        }
        if self == Self::Grants {
            return Some(conformance_grant_identity());
        }
        let mut builder = IdentityImpl::builder()
            .resolve_token(std::sync::Arc::new(conformance_resolve_token))
            .introspect_principals([INTROSPECTOR_PRINCIPAL])
            .max_auth_age(std::time::Duration::from_secs(MAX_AUTH_AGE_SECONDS));
        if self == Self::Both {
            builder = builder.mint_grant(std::sync::Arc::new(conformance_mint_grant));
        }
        Some(builder.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_host_what_their_hooks_justify() {
        assert!(IdentityMode::Off.build().is_none());
        let both = IdentityMode::Both.build().expect("configured");
        assert_eq!(both.offered_methods().len(), 2);
        let narrowed = IdentityMode::IntrospectOnly.build().expect("configured");
        assert_eq!(
            narrowed.offered_methods().into_iter().collect::<Vec<_>>(),
            vec!["introspect_token"]
        );
    }
}
