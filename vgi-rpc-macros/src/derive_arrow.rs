//! `#[derive(VgiArrow)]` for plain structs.
//!
//! Generates an `impl VgiArrow for MyStruct` with:
//! - `arrow_data_type()` returning `DataType::Struct(Fields)` built
//!   from each field's `VgiArrow::arrow_data_type` + `nullable`.
//! - `describe_name()` returning the struct's name (or the
//!   `#[vgi_arrow(name = "...")]` override).
//! - `read(arr, idx)` downcasting to `StructArray` and delegating to
//!   each field's `read`.
//! - `build_singleton(value)` building a `StructArray` from each
//!   field's `build_singleton`.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{parse_macro_input, Data, DeriveInput, Fields, Lit, Meta, MetaNameValue};

pub fn derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(&input) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let struct_name = &input.ident;
    let describe_name = parse_describe_name(input)?.unwrap_or_else(|| struct_name.to_string());

    let fields = match &input.data {
        Data::Struct(s) => match &s.fields {
            Fields::Named(named) => &named.named,
            Fields::Unnamed(_) => {
                return Err(syn::Error::new_spanned(
                    struct_name,
                    "VgiArrow can only be derived for structs with named fields",
                ));
            }
            Fields::Unit => {
                return Err(syn::Error::new_spanned(
                    struct_name,
                    "VgiArrow cannot be derived for unit structs",
                ));
            }
        },
        Data::Enum(_) | Data::Union(_) => {
            return Err(syn::Error::new_spanned(
                struct_name,
                "VgiArrow can only be derived for structs",
            ));
        }
    };

    if fields.is_empty() {
        return Err(syn::Error::new_spanned(
            struct_name,
            "VgiArrow requires at least one field",
        ));
    }

    // Per-field codegen pieces.
    let mut field_definitions = Vec::new(); // for arrow_data_type()
    let mut field_reads = Vec::new(); // for read()
    let mut field_builds = Vec::new(); // for build_singleton()
    let mut field_idents = Vec::new(); // for the constructor

    for f in fields {
        let ident = f.ident.as_ref().expect("named field");
        let ident_str = ident.to_string();
        let ty = &f.ty;

        field_idents.push(ident.clone());

        field_definitions.push(quote! {
            ::arrow_schema::Field::new(
                #ident_str,
                <#ty as ::vgi_rpc::VgiArrow>::arrow_data_type(),
                <#ty as ::vgi_rpc::VgiArrow>::nullable(),
            )
        });

        field_reads.push(quote! {
            let #ident: #ty = <#ty as ::vgi_rpc::VgiArrow>::read(
                __struct
                    .column_by_name(#ident_str)
                    .ok_or_else(|| ::vgi_rpc::RpcError::type_error(
                        format!("{} missing field {}", #describe_name, #ident_str)
                    ))?
                    .as_ref(),
                idx,
            )?;
        });

        // For build_singleton: capture per-field 1-row arrays into
        // (Field, ArrayRef) pairs that StructArray::from accepts.
        let build_field_ident = format_ident!("__field_{}", ident);
        field_builds.push(quote! {
            let #build_field_ident: ::arrow_array::ArrayRef =
                <#ty as ::vgi_rpc::VgiArrow>::build_singleton(value.#ident)?;
        });
    }

    // Reconstruct field idents for use after the build closures.
    let build_pairs = fields.iter().map(|f| {
        let ident = f.ident.as_ref().unwrap();
        let ident_str = ident.to_string();
        let ty = &f.ty;
        let build_field_ident = format_ident!("__field_{}", ident);
        quote! {
            (
                ::std::sync::Arc::new(::arrow_schema::Field::new(
                    #ident_str,
                    <#ty as ::vgi_rpc::VgiArrow>::arrow_data_type(),
                    <#ty as ::vgi_rpc::VgiArrow>::nullable(),
                )),
                #build_field_ident,
            )
        }
    });

    let expanded = quote! {
        impl ::vgi_rpc::VgiArrow for #struct_name {
            fn arrow_data_type() -> ::arrow_schema::DataType {
                ::arrow_schema::DataType::Struct(
                    ::arrow_schema::Fields::from(vec![
                        #(#field_definitions),*
                    ])
                )
            }

            fn describe_name() -> ::std::string::String {
                #describe_name.into()
            }

            fn read(
                arr: &dyn ::arrow_array::Array,
                idx: usize,
            ) -> ::vgi_rpc::Result<Self> {
                let __struct = arr
                    .as_any()
                    .downcast_ref::<::arrow_array::StructArray>()
                    .ok_or_else(|| ::vgi_rpc::RpcError::type_error(
                        format!("expected Struct array for {}", #describe_name)
                    ))?;
                #(#field_reads)*
                Ok(Self { #(#field_idents),* })
            }

            fn build_singleton(
                value: Self,
            ) -> ::vgi_rpc::Result<::arrow_array::ArrayRef> {
                #(#field_builds)*
                let __pairs: ::std::vec::Vec<(
                    ::std::sync::Arc<::arrow_schema::Field>,
                    ::arrow_array::ArrayRef,
                )> = vec![#(#build_pairs),*];
                let __struct = ::arrow_array::StructArray::from(__pairs);
                Ok(::std::sync::Arc::new(__struct))
            }
        }
    };

    Ok(expanded)
}

fn parse_describe_name(input: &DeriveInput) -> syn::Result<Option<String>> {
    for attr in &input.attrs {
        if !attr.path().is_ident("vgi_arrow") {
            continue;
        }
        let mut found: Option<String> = None;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("name") {
                let value = meta.value()?;
                let lit: Lit = value.parse()?;
                match lit {
                    Lit::Str(s) => {
                        found = Some(s.value());
                        Ok(())
                    }
                    other => Err(syn::Error::new_spanned(
                        other,
                        "vgi_arrow(name = ...) must be a string literal",
                    )),
                }
            } else {
                Err(meta.error("unsupported vgi_arrow attribute (expected `name = \"...\"`)"))
            }
        })?;
        return Ok(found);
    }
    // Suppress unused-import warning from syn::MetaNameValue / Meta paths
    // when `vgi_arrow(...)` is absent.
    let _ = std::marker::PhantomData::<(MetaNameValue, Meta)>;
    Ok(None)
}
