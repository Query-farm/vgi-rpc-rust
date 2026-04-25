//! `#[derive(StreamState)]` — auto-impls `StreamStateCodec` (bincode by
//! default) for a state struct, eliminating the per-state
//! `impl_bincode_codec!` boilerplate.
//!
//! The derived impl forwards `encode` / `decode` to the bincode helpers
//! in `vgi_rpc::stream_codec`. Container attributes:
//!
//! - `#[stream_state(rebuild = "fn_path")]` — after decode, calls
//!   `fn_path(&mut self)` so dynamic-schema states can re-derive their
//!   `SchemaRef` from the deserialized fields.
//!
//! Field attributes:
//!
//! - `#[stream_state(skip)]` — equivalent to `#[serde(skip)]`. Field
//!   must implement `Default`.
//!
//! Requires the struct itself to derive `serde::Serialize, serde::Deserialize`
//! since the codec is bincode-backed.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Lit};

pub fn derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let name = &input.ident;
    let rebuild = parse_rebuild(input)?;

    let decode_body = match rebuild {
        Some(path) => quote! {
            let mut __value: Self = ::vgi_rpc::stream_codec::bincode_decode(bytes)?;
            #path(&mut __value);
            Ok(__value)
        },
        None => quote! {
            ::vgi_rpc::stream_codec::bincode_decode(bytes)
        },
    };

    let expanded = quote! {
        impl ::vgi_rpc::stream_codec::StreamStateCodec for #name {
            fn encode(&self) -> ::vgi_rpc::Result<::std::vec::Vec<u8>> {
                ::vgi_rpc::stream_codec::bincode_encode(self)
            }
            fn decode(bytes: &[u8]) -> ::vgi_rpc::Result<Self> {
                #decode_body
            }
        }
    };
    Ok(expanded)
}

fn parse_rebuild(input: &DeriveInput) -> syn::Result<Option<syn::Path>> {
    let mut found: Option<syn::Path> = None;
    for attr in &input.attrs {
        if !attr.path().is_ident("stream_state") {
            continue;
        }
        attr.parse_nested_meta(|m| {
            if m.path.is_ident("rebuild") {
                let value = m.value()?;
                let lit: Lit = value.parse()?;
                match lit {
                    Lit::Str(s) => {
                        found = Some(s.parse::<syn::Path>()?);
                        Ok(())
                    }
                    other => Err(syn::Error::new_spanned(
                        other,
                        "stream_state(rebuild = \"fn_path\") must be a string literal",
                    )),
                }
            } else {
                Err(m.error("expected `rebuild = \"fn_path\"`"))
            }
        })?;
    }
    Ok(found)
}
