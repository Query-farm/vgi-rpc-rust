//! `#[service]` attribute applied to an `impl` block, plus the
//! marker attributes (`#[unary]`, `#[producer]`, `#[exchange]`,
//! `#[param]`) consumed by the service-level scan.
//!
//! Phase 3 lands `#[unary]`. Phase 5 adds `#[producer]` / `#[exchange]`.
//! The marker attribute proc-macros pass their input through unchanged
//! so they don't error if used outside an `#[service]` impl — the real
//! compile-time enforcement happens during the service-level scan.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{parse_macro_input, Attribute, FnArg, ImplItem, ItemImpl, Pat, Type};

pub fn passthrough(item: TokenStream) -> TokenStream {
    item
}

pub fn expand(_args: TokenStream, item: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(item as ItemImpl);
    match expand_impl(&mut input) {
        Ok(extra) => {
            let original = quote! { #input };
            let combined = quote! {
                #original
                #extra
            };
            combined.into()
        }
        Err(e) => {
            let err = e.to_compile_error();
            let original = quote! { #input };
            quote! {
                #original
                #err
            }
            .into()
        }
    }
}

fn expand_impl(input: &mut ItemImpl) -> syn::Result<TokenStream2> {
    // Self type — must be a path so we can name it for the generated impl.
    let self_ty = &*input.self_ty;
    if !matches!(self_ty, Type::Path(_)) {
        return Err(syn::Error::new_spanned(
            self_ty,
            "#[service] must be applied to `impl SomeType { ... }` (no trait impls or generics yet)",
        ));
    }

    let mut method_specs: Vec<MethodSpec> = Vec::new();
    let mut helper_fns: Vec<TokenStream2> = Vec::new();

    for item in &mut input.items {
        let ImplItem::Fn(method) = item else { continue };

        // Pull off the kind attribute (`#[unary]` / `#[producer]` / `#[exchange]`).
        let Some(kind_attr_idx) = method.attrs.iter().position(is_kind_attr) else {
            continue;
        };
        let kind_attr = method.attrs.remove(kind_attr_idx);
        let stream_meta = parse_stream_meta(&kind_attr)?;
        let kind = parse_kind(&kind_attr)?;

        // Extract any `#[param(...)]` attributes (per-parameter metadata).
        let param_meta = take_param_attrs(&mut method.attrs)?;

        // Doc comment.
        let doc = collect_doc(&method.attrs);

        let sig = &method.sig;
        let method_name = sig.ident.to_string();
        let inst_method = sig.ident.clone();

        let is_async = sig.asyncness.is_some();

        // Parse params (skip &self / &mut self).
        let params = parse_params(sig, &param_meta)?;

        match kind {
            MethodKind::Unary => {
                let (helper_fn, registration) =
                    build_unary(&inst_method, &method_name, &doc, &params, sig, is_async)?;
                helper_fns.push(helper_fn);
                method_specs.push(MethodSpec { registration });
            }
            MethodKind::Producer => {
                let registration = build_stream(
                    StreamShape::Producer,
                    &inst_method,
                    &method_name,
                    &doc,
                    &params,
                    &stream_meta,
                    &kind_attr,
                    is_async,
                )?;
                method_specs.push(MethodSpec { registration });
            }
            MethodKind::Exchange => {
                let registration = build_stream(
                    StreamShape::Exchange,
                    &inst_method,
                    &method_name,
                    &doc,
                    &params,
                    &stream_meta,
                    &kind_attr,
                    is_async,
                )?;
                method_specs.push(MethodSpec { registration });
            }
        }
    }

    if method_specs.is_empty() {
        return Ok(quote! {});
    }

    let registrations = method_specs.into_iter().map(|s| s.registration);

    let expanded = quote! {
        #(#helper_fns)*

        impl #self_ty {
            /// Register every method tagged with `#[unary]` /
            /// `#[producer]` / `#[exchange]` against `server`. Generated
            /// by `#[vgi_rpc::service]`.
            pub fn register_with(
                server: &mut ::vgi_rpc::RpcServer,
                instance: ::std::sync::Arc<Self>,
            ) {
                #(#registrations)*
            }
        }
    };

    Ok(expanded)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MethodKind {
    Unary,
    Producer,
    Exchange,
}

struct MethodSpec {
    registration: TokenStream2,
}

struct ParamSpec {
    ident: syn::Ident,
    ty: Type,
    name: String,
    doc: Option<String>,
    default: Option<syn::Expr>,
    /// Override for the describe-format type name. Default uses
    /// `<T as VgiArrow>::describe_name()` at runtime; set this to a
    /// string literal when you want the wire-format type to differ
    /// (e.g. `"Status"` for an enum carried as `Utf8`, or `"Point"`
    /// for a dataclass carried as `Binary`).
    arrow_type_override: Option<String>,
    /// `true` when the param is `ctx: &CallContext` and should be
    /// supplied from the closure's `ctx` arg rather than read from
    /// the request batch.
    is_ctx: bool,
}

#[derive(Default)]
struct ParamMetaMap {
    entries: Vec<(String, ParamMeta)>,
}

#[derive(Default)]
struct ParamMeta {
    name_override: Option<String>,
    doc: Option<String>,
    default: Option<syn::Expr>,
    arrow_type_override: Option<String>,
}

fn is_kind_attr(attr: &Attribute) -> bool {
    attr.path().is_ident("unary")
        || attr.path().is_ident("producer")
        || attr.path().is_ident("exchange")
}

fn parse_kind(attr: &Attribute) -> syn::Result<MethodKind> {
    if attr.path().is_ident("unary") {
        Ok(MethodKind::Unary)
    } else if attr.path().is_ident("producer") {
        Ok(MethodKind::Producer)
    } else if attr.path().is_ident("exchange") {
        Ok(MethodKind::Exchange)
    } else {
        Err(syn::Error::new_spanned(attr, "unknown method kind"))
    }
}

fn take_param_attrs(attrs: &mut Vec<Attribute>) -> syn::Result<ParamMetaMap> {
    let mut out = ParamMetaMap::default();
    let mut i = 0;
    while i < attrs.len() {
        if attrs[i].path().is_ident("param") {
            let attr = attrs.remove(i);
            let mut meta = ParamMeta::default();
            let mut bound_param: Option<String> = None;
            attr.parse_nested_meta(|m| {
                if m.path.is_ident("name") {
                    let value = m.value()?;
                    let lit: syn::LitStr = value.parse()?;
                    bound_param = Some(lit.value());
                    Ok(())
                } else if m.path.is_ident("doc") {
                    let value = m.value()?;
                    let lit: syn::LitStr = value.parse()?;
                    meta.doc = Some(lit.value());
                    Ok(())
                } else if m.path.is_ident("default") {
                    let value = m.value()?;
                    let expr: syn::Expr = value.parse()?;
                    meta.default = Some(expr);
                    Ok(())
                } else if m.path.is_ident("rename") {
                    let value = m.value()?;
                    let lit: syn::LitStr = value.parse()?;
                    meta.name_override = Some(lit.value());
                    Ok(())
                } else if m.path.is_ident("arrow_type") {
                    let value = m.value()?;
                    let lit: syn::LitStr = value.parse()?;
                    meta.arrow_type_override = Some(lit.value());
                    Ok(())
                } else {
                    Err(m.error("expected name, doc, default, rename, or arrow_type"))
                }
            })?;
            let bound_param = bound_param.ok_or_else(|| {
                syn::Error::new_spanned(&attr, "#[param] must include `name = \"<param_ident>\"`")
            })?;
            out.entries.push((bound_param, meta));
        } else {
            i += 1;
        }
    }
    Ok(out)
}

fn collect_doc(attrs: &[Attribute]) -> Option<String> {
    let mut lines = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("doc") {
            continue;
        }
        if let syn::Meta::NameValue(nv) = &attr.meta {
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) = &nv.value
            {
                lines.push(s.value().trim().to_string());
            }
        }
    }
    if lines.is_empty() {
        None
    } else {
        // Match the Python convention: docstring is the first non-empty line.
        lines.iter().find(|l| !l.is_empty()).cloned()
    }
}

fn parse_params(sig: &syn::Signature, meta: &ParamMetaMap) -> syn::Result<Vec<ParamSpec>> {
    let mut out = Vec::new();
    for arg in sig.inputs.iter() {
        match arg {
            FnArg::Receiver(_) => continue,
            FnArg::Typed(pt) => {
                let ident = match &*pt.pat {
                    Pat::Ident(p) => p.ident.clone(),
                    other => {
                        return Err(syn::Error::new_spanned(
                            other,
                            "service-method params must be plain identifiers",
                        ));
                    }
                };
                // Strip Rust raw-identifier prefix `r#` for wire / describe name.
                let ident_str = ident.to_string().trim_start_matches("r#").to_string();
                let ty: Type = (*pt.ty).clone();
                let is_ctx = is_call_context_ref(&ty);
                let entry = meta
                    .entries
                    .iter()
                    .find(|(k, _)| k == &ident_str)
                    .map(|(_, m)| m);
                let name = entry
                    .and_then(|m| m.name_override.clone())
                    .unwrap_or_else(|| ident_str.clone());
                let doc = entry.and_then(|m| m.doc.clone());
                let default = entry.and_then(|m| m.default.clone());
                let arrow_type_override = entry.and_then(|m| m.arrow_type_override.clone());
                out.push(ParamSpec {
                    ident,
                    ty,
                    name,
                    doc,
                    default,
                    arrow_type_override,
                    is_ctx,
                });
            }
        }
    }
    Ok(out)
}

/// Detect `&CallContext` / `&vgi_rpc::CallContext` / `&vgi_rpc::server::CallContext`.
fn is_call_context_ref(ty: &Type) -> bool {
    let Type::Reference(r) = ty else {
        return false;
    };
    let Type::Path(path) = &*r.elem else {
        return false;
    };
    path.path
        .segments
        .last()
        .map(|s| s.ident == "CallContext")
        .unwrap_or(false)
}

fn build_unary(
    inst_method: &syn::Ident,
    method_name: &str,
    doc: &Option<String>,
    params: &[ParamSpec],
    sig: &syn::Signature,
    is_async: bool,
) -> syn::Result<(TokenStream2, TokenStream2)> {
    // Result type — extract the inner T from `Result<T>` / `Result<T, E>`.
    let return_ty = parse_return_type(sig)?;

    let params_schema_fn = format_ident!("__vgi_{}_params_schema", inst_method);
    let result_schema_fn = format_ident!("__vgi_{}_result_schema", inst_method);

    // Build params schema (skip ctx params).
    let param_field_defs = params.iter().filter(|p| !p.is_ctx).map(|p| {
        let ty = &p.ty;
        let name = &p.name;
        quote! {
            ::arrow_schema::Field::new(
                #name,
                <#ty as ::vgi_rpc::VgiArrow>::arrow_data_type(),
                <#ty as ::vgi_rpc::VgiArrow>::nullable(),
            )
        }
    });
    let any_arrow_params = params.iter().any(|p| !p.is_ctx);
    let params_schema_body = if !any_arrow_params {
        quote! { ::std::sync::Arc::new(::arrow_schema::Schema::empty()) }
    } else {
        quote! {
            ::std::sync::Arc::new(::arrow_schema::Schema::new(vec![
                #(#param_field_defs),*
            ]))
        }
    };

    let helper_fns = match &return_ty {
        ReturnSpec::Value(ty) => {
            quote! {
                #[doc(hidden)]
                fn #params_schema_fn() -> ::arrow_schema::SchemaRef {
                    #params_schema_body
                }
                #[doc(hidden)]
                fn #result_schema_fn() -> ::arrow_schema::SchemaRef {
                    ::std::sync::Arc::new(::arrow_schema::Schema::new(vec![
                        ::arrow_schema::Field::new(
                            "result",
                            <#ty as ::vgi_rpc::VgiArrow>::arrow_data_type(),
                            <#ty as ::vgi_rpc::VgiArrow>::nullable(),
                        )
                    ]))
                }
            }
        }
        ReturnSpec::Void => {
            quote! {
                #[doc(hidden)]
                fn #params_schema_fn() -> ::arrow_schema::SchemaRef {
                    #params_schema_body
                }
                #[doc(hidden)]
                fn #result_schema_fn() -> ::arrow_schema::SchemaRef {
                    ::std::sync::Arc::new(::arrow_schema::Schema::empty())
                }
            }
        }
    };

    // Per-param read (skip ctx params).
    let param_reads = params.iter().filter(|p| !p.is_ctx).map(|p| {
        let ident = &p.ident;
        let ty = &p.ty;
        let name = &p.name;
        quote! {
            let #ident: #ty = <#ty as ::vgi_rpc::VgiArrow>::read(
                req
                    .column(#name)
                    .ok_or_else(|| ::vgi_rpc::RpcError::type_error(
                        format!("missing param {}", #name)
                    ))?,
                0,
            )?;
        }
    });

    // Forward each declared param to the user's method, in source
    // order. Ctx params resolve to the closure's `_ctx` arg.
    let param_idents: Vec<_> = params.iter().map(|p| p.ident.clone()).collect();
    let call_args: Vec<TokenStream2> = params
        .iter()
        .map(|p| {
            let ident = &p.ident;
            if p.is_ctx {
                quote! { _ctx }
            } else {
                quote! { #ident }
            }
        })
        .collect();

    let call_inst = if is_async {
        quote! {
            ::tokio::task::block_in_place(|| {
                ::tokio::runtime::Handle::current()
                    .block_on(async { inst.#inst_method(#(#call_args),*).await })
            })?
        }
    } else {
        quote! { inst.#inst_method(#(#call_args),*)? }
    };
    let call_inst_void = if is_async {
        quote! {
            ::tokio::task::block_in_place(|| {
                ::tokio::runtime::Handle::current()
                    .block_on(async { inst.#inst_method(#(#call_args),*).await })
            })?;
        }
    } else {
        quote! { inst.#inst_method(#(#call_args),*)?; }
    };
    let _ = param_idents;
    let handler_body = match &return_ty {
        ReturnSpec::Value(ty) => quote! {
            #(#param_reads)*
            let __out: #ty = #call_inst;
            let __arr = <#ty as ::vgi_rpc::VgiArrow>::build_singleton(__out)?;
            let __batch = ::arrow_array::RecordBatch::try_new(
                #result_schema_fn(),
                vec![__arr],
            )?;
            Ok(Some(__batch))
        },
        ReturnSpec::Void => quote! {
            #(#param_reads)*
            #call_inst_void
            Ok(None)
        },
    };

    // Build the .doc().param_type().param_doc().param_default() chain.
    let doc_call = doc
        .as_ref()
        .map(|d| quote! { .doc(#d) })
        .unwrap_or_else(|| quote! {});

    let param_type_calls = params.iter().filter(|p| !p.is_ctx).map(|p| {
        let ty = &p.ty;
        let name = &p.name;
        match &p.arrow_type_override {
            Some(s) => quote! { .param_type(#name, #s) },
            None => quote! {
                .param_type(#name, <#ty as ::vgi_rpc::VgiArrow>::describe_name())
            },
        }
    });

    let param_doc_calls = params.iter().filter(|p| !p.is_ctx).filter_map(|p| {
        let name = &p.name;
        p.doc.as_ref().map(|d| {
            quote! {
                .param_doc(#name, #d)
            }
        })
    });

    let param_default_calls = params.iter().filter(|p| !p.is_ctx).filter_map(|p| {
        let name = &p.name;
        p.default.as_ref().map(|expr| {
            quote! {
                .param_default(#name, ::serde_json::json!(#expr))
            }
        })
    });

    let registration = quote! {
        {
            let __inst = ::std::sync::Arc::clone(&instance);
            server.register(
                ::vgi_rpc::MethodInfo::unary(
                    #method_name,
                    #params_schema_fn(),
                    #result_schema_fn(),
                    move |req, _ctx| -> ::vgi_rpc::Result<Option<::arrow_array::RecordBatch>> {
                        let inst = ::std::sync::Arc::clone(&__inst);
                        #handler_body
                    },
                )
                #doc_call
                #(#param_type_calls)*
                #(#param_doc_calls)*
                #(#param_default_calls)*
            );
        }
    };

    Ok((helper_fns, registration))
}

// `Value` wraps a (large) `syn::Type` next to the unit `Void`; this is a
// compile-time AST tag built once per method, so the size delta the
// `large_enum_variant` lint flags is irrelevant here.
#[allow(clippy::large_enum_variant)]
enum ReturnSpec {
    Value(Type),
    Void,
}

/// Extract `T` from `-> Result<T>` or `-> Result<T, E>`. Treats
/// `-> Result<()>` as `ReturnSpec::Void`.
fn parse_return_type(sig: &syn::Signature) -> syn::Result<ReturnSpec> {
    let ret = match &sig.output {
        syn::ReturnType::Default => {
            return Err(syn::Error::new_spanned(
                &sig.ident,
                "service methods must return Result<T> (or Result<T, E>); '-> ()' isn't allowed — use Result<()>",
            ));
        }
        syn::ReturnType::Type(_, ty) => ty.as_ref(),
    };
    let path = match ret {
        Type::Path(tp) => &tp.path,
        other => {
            return Err(syn::Error::new_spanned(
                other,
                "service methods must return Result<T>",
            ));
        }
    };
    let last = path
        .segments
        .last()
        .ok_or_else(|| syn::Error::new_spanned(path, "service methods must return Result<T>"))?;
    if last.ident != "Result" {
        return Err(syn::Error::new_spanned(
            &last.ident,
            "service methods must return Result<T>",
        ));
    }
    let args = match &last.arguments {
        syn::PathArguments::AngleBracketed(a) => &a.args,
        _ => {
            return Err(syn::Error::new_spanned(
                last,
                "service methods must return Result<T>",
            ));
        }
    };
    let first = args.first().ok_or_else(|| {
        syn::Error::new_spanned(last, "Result requires at least one type parameter")
    })?;
    let inner_ty = match first {
        syn::GenericArgument::Type(t) => t.clone(),
        other => {
            return Err(syn::Error::new_spanned(
                other,
                "Result's first type argument must be a type",
            ));
        }
    };
    // Unit-type return → void.
    if let Type::Tuple(tup) = &inner_ty {
        if tup.elems.is_empty() {
            return Ok(ReturnSpec::Void);
        }
    }
    Ok(ReturnSpec::Value(inner_ty))
}

// ---------------------------------------------------------------------------
// Streaming methods (Phase 5+)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct StreamMeta {
    state: Option<Type>,
    output: Option<Type>,
    output_schema_fn: Option<syn::Path>,
    input: Option<Type>,
    input_schema_fn: Option<syn::Path>,
    /// Header type (single-column wrapper; for multi-column headers
    /// pair `header_schema = ...` with a header_fn returning a
    /// `RecordBatch`).
    header: Option<Type>,
    header_fn: Option<syn::Path>,
    /// Path to a `fn() -> SchemaRef` for multi-column header schemas.
    /// When set, `header_fn` must return `Result<RecordBatch>`.
    header_schema_fn: Option<syn::Path>,
    dynamic: bool,
    schema_fn: Option<syn::Path>,
}

fn parse_stream_meta(attr: &Attribute) -> syn::Result<StreamMeta> {
    let mut meta = StreamMeta::default();
    if matches!(&attr.meta, syn::Meta::Path(_)) {
        // bare `#[unary]` / `#[producer]` / `#[exchange]` — no nested args.
        return Ok(meta);
    }
    attr.parse_nested_meta(|m| {
        if m.path.is_ident("state") {
            let value = m.value()?;
            meta.state = Some(value.parse()?);
            Ok(())
        } else if m.path.is_ident("output") {
            let value = m.value()?;
            meta.output = Some(value.parse()?);
            Ok(())
        } else if m.path.is_ident("output_schema") {
            let value = m.value()?;
            meta.output_schema_fn = Some(value.parse()?);
            Ok(())
        } else if m.path.is_ident("input") {
            let value = m.value()?;
            meta.input = Some(value.parse()?);
            Ok(())
        } else if m.path.is_ident("input_schema") {
            let value = m.value()?;
            meta.input_schema_fn = Some(value.parse()?);
            Ok(())
        } else if m.path.is_ident("header") {
            let value = m.value()?;
            meta.header = Some(value.parse()?);
            Ok(())
        } else if m.path.is_ident("header_fn") {
            let value = m.value()?;
            meta.header_fn = Some(value.parse()?);
            Ok(())
        } else if m.path.is_ident("header_schema") {
            let value = m.value()?;
            meta.header_schema_fn = Some(value.parse()?);
            Ok(())
        } else if m.path.is_ident("dynamic") {
            meta.dynamic = true;
            Ok(())
        } else if m.path.is_ident("schema_fn") {
            let value = m.value()?;
            meta.schema_fn = Some(value.parse()?);
            Ok(())
        } else if m.path.is_ident("no_return") {
            // unary marker — handled elsewhere.
            Ok(())
        } else {
            Err(m.error("expected state / output / input / output_schema / input_schema / header / header_fn / dynamic / schema_fn"))
        }
    })?;
    Ok(meta)
}

#[derive(Clone, Copy)]
enum StreamShape {
    Producer,
    Exchange,
}

#[allow(clippy::too_many_arguments)]
fn build_stream(
    shape: StreamShape,
    inst_method: &syn::Ident,
    method_name: &str,
    doc: &Option<String>,
    params: &[ParamSpec],
    meta: &StreamMeta,
    kind_attr: &Attribute,
    is_async: bool,
) -> syn::Result<TokenStream2> {
    let state_ty = meta.state.as_ref().ok_or_else(|| {
        syn::Error::new_spanned(
            kind_attr,
            "stream methods require `state = <StateType>` (the user-defined ProducerState/ExchangeState type)",
        )
    })?;

    // Header support has two modes:
    //   1. `header = T, header_fn = path` — T: VgiArrow, single-column wrapper
    //   2. `header_schema = path, header_fn = path` — custom multi-column
    //      schema; header_fn returns Result<RecordBatch>.
    let header_uses_record_batch = meta.header_schema_fn.is_some();
    if meta.header.is_some() && header_uses_record_batch {
        return Err(syn::Error::new_spanned(
            kind_attr,
            "`header = <Type>` and `header_schema = <fn_path>` are mutually exclusive — pick one",
        ));
    }
    let any_header = meta.header.is_some() || header_uses_record_batch;
    if any_header != meta.header_fn.is_some() {
        return Err(syn::Error::new_spanned(
            kind_attr,
            "`header_fn = <fn_path>` must be paired with either `header = <Type>` or `header_schema = <fn_path>`",
        ));
    }

    // dynamic must be paired with schema_fn for producers.
    if meta.dynamic && meta.schema_fn.is_none() {
        return Err(syn::Error::new_spanned(
            kind_attr,
            "`dynamic` requires `schema_fn = <fn_path>` returning Result<SchemaRef> from a request",
        ));
    }
    if meta.dynamic && matches!(shape, StreamShape::Exchange) {
        return Err(syn::Error::new_spanned(
            kind_attr,
            "`dynamic` is only valid on `#[producer(...)]`",
        ));
    }

    let params_schema_fn = format_ident!("__vgi_{}_params_schema", inst_method);
    let output_schema_fn_ident = format_ident!("__vgi_{}_output_schema", inst_method);
    let input_schema_fn_ident = format_ident!("__vgi_{}_input_schema", inst_method);

    // Build params schema (skip ctx params).
    let param_field_defs = params.iter().filter(|p| !p.is_ctx).map(|p| {
        let ty = &p.ty;
        let name = &p.name;
        quote! {
            ::arrow_schema::Field::new(
                #name,
                <#ty as ::vgi_rpc::VgiArrow>::arrow_data_type(),
                <#ty as ::vgi_rpc::VgiArrow>::nullable(),
            )
        }
    });
    let any_arrow_params = params.iter().any(|p| !p.is_ctx);
    let params_schema_body = if !any_arrow_params {
        quote! { ::std::sync::Arc::new(::arrow_schema::Schema::empty()) }
    } else {
        quote! {
            ::std::sync::Arc::new(::arrow_schema::Schema::new(vec![
                #(#param_field_defs),*
            ]))
        }
    };

    // Output-schema body. Three options, in priority order:
    //   1. `output_schema = path::to::fn` — call user fn.
    //   2. `output = T` — single-column "value" of type T.
    //   3. dynamic — schema computed at init via `schema_fn`; the static
    //      helper just returns an empty schema as a placeholder for
    //      describe metadata.
    //   4. none of the above — error.
    let output_schema_body = if let Some(path) = meta.output_schema_fn.as_ref() {
        quote! { #path() }
    } else if let Some(out_ty) = meta.output.as_ref() {
        quote! {
            ::std::sync::Arc::new(::arrow_schema::Schema::new(vec![
                ::arrow_schema::Field::new(
                    "value",
                    <#out_ty as ::vgi_rpc::VgiArrow>::arrow_data_type(),
                    <#out_ty as ::vgi_rpc::VgiArrow>::nullable(),
                )
            ]))
        }
    } else if meta.dynamic {
        quote! { ::std::sync::Arc::new(::arrow_schema::Schema::empty()) }
    } else {
        return Err(syn::Error::new_spanned(
            kind_attr,
            "stream method needs either `output = <Type>` or `output_schema = <fn_path>` (or `dynamic`)",
        ));
    };

    // Input-schema body (exchange only).
    let input_schema_body = match shape {
        StreamShape::Producer => quote! {},
        StreamShape::Exchange => {
            let body = if let Some(path) = meta.input_schema_fn.as_ref() {
                quote! { #path() }
            } else if let Some(in_ty) = meta.input.as_ref() {
                quote! {
                    ::std::sync::Arc::new(::arrow_schema::Schema::new(vec![
                        ::arrow_schema::Field::new(
                            "value",
                            <#in_ty as ::vgi_rpc::VgiArrow>::arrow_data_type(),
                            <#in_ty as ::vgi_rpc::VgiArrow>::nullable(),
                        )
                    ]))
                }
            } else {
                return Err(syn::Error::new_spanned(
                    kind_attr,
                    "exchange method needs either `input = <Type>` or `input_schema = <fn_path>`",
                ));
            };
            quote! {
                #[doc(hidden)]
                fn #input_schema_fn_ident() -> ::arrow_schema::SchemaRef {
                    #body
                }
            }
        }
    };

    let helper_fns = quote! {
        #[doc(hidden)]
        fn #params_schema_fn() -> ::arrow_schema::SchemaRef {
            #params_schema_body
        }
        #[doc(hidden)]
        fn #output_schema_fn_ident() -> ::arrow_schema::SchemaRef {
            #output_schema_body
        }
        #input_schema_body
    };

    // Param reads (skip ctx).
    let param_reads = params.iter().filter(|p| !p.is_ctx).map(|p| {
        let ident = &p.ident;
        let ty = &p.ty;
        let name = &p.name;
        quote! {
            let #ident: #ty = <#ty as ::vgi_rpc::VgiArrow>::read(
                req
                    .column(#name)
                    .ok_or_else(|| ::vgi_rpc::RpcError::type_error(
                        format!("missing param {}", #name)
                    ))?,
                0,
            )?;
        }
    });
    let param_idents: Vec<TokenStream2> = params
        .iter()
        .map(|p| {
            let ident = &p.ident;
            if p.is_ctx {
                quote! { _ctx }
            } else {
                quote! { #ident }
            }
        })
        .collect();

    // Compute the runtime output schema. For dynamic producers,
    // call the user-supplied schema_fn at init time; otherwise use
    // the static helper fn.
    let output_schema_at_runtime: TokenStream2 = if meta.dynamic {
        let schema_fn = meta
            .schema_fn
            .as_ref()
            .expect("dynamic without schema_fn (validated above)");
        quote! { #schema_fn(req)? }
    } else {
        quote! { #output_schema_fn_ident() }
    };

    // Header: build the header batch and attach via .with_header(...).
    let header_chain: TokenStream2 = if let Some(header_fn) = meta.header_fn.as_ref() {
        if let Some(_schema_fn) = meta.header_schema_fn.as_ref() {
            // Custom multi-column schema: header_fn returns RecordBatch.
            quote! {
                {
                    let __h_batch: ::arrow_array::RecordBatch = #header_fn(req)?;
                    __sr = __sr.with_header(__h_batch);
                }
            }
        } else {
            let header_ty = meta
                .header
                .as_ref()
                .expect("header_fn without header (validated above)");
            quote! {
                {
                    let __h: #header_ty = #header_fn(req)?;
                    let __h_arr = <#header_ty as ::vgi_rpc::VgiArrow>::build_singleton(__h)?;
                    let __h_schema = ::std::sync::Arc::new(::arrow_schema::Schema::new(vec![
                        ::arrow_schema::Field::new(
                            "value",
                            <#header_ty as ::vgi_rpc::VgiArrow>::arrow_data_type(),
                            <#header_ty as ::vgi_rpc::VgiArrow>::nullable(),
                        )
                    ]));
                    let __h_batch = ::arrow_array::RecordBatch::try_new(__h_schema, vec![__h_arr])?;
                    __sr = __sr.with_header(__h_batch);
                }
            }
        }
    } else {
        quote! {}
    };

    // Init closure body and StreamResult constructor.
    let (method_type_variant, stream_result_ctor, decoder_helper) = match shape {
        StreamShape::Producer => {
            let mt = if meta.dynamic {
                quote! { ::vgi_rpc::MethodType::Dynamic }
            } else {
                quote! { ::vgi_rpc::MethodType::Producer }
            };
            (
                mt,
                quote! {
                    let mut __sr = ::vgi_rpc::StreamResult::producer(
                        #output_schema_at_runtime,
                        Box::new(__state),
                    );
                    #header_chain
                    Ok(__sr)
                },
                quote! { ::vgi_rpc::stream::producer_decoder::<#state_ty>() },
            )
        }
        StreamShape::Exchange => (
            quote! { ::vgi_rpc::MethodType::Exchange },
            quote! {
                let mut __sr = ::vgi_rpc::StreamResult::exchange(
                    #output_schema_fn_ident(),
                    #input_schema_fn_ident(),
                    Box::new(__state),
                );
                #header_chain
                Ok(__sr)
            },
            quote! { ::vgi_rpc::stream::exchange_decoder::<#state_ty>() },
        ),
    };

    let doc_call = doc
        .as_ref()
        .map(|d| quote! { .doc(#d) })
        .unwrap_or_else(|| quote! {});

    let param_type_calls = params.iter().filter(|p| !p.is_ctx).map(|p| {
        let ty = &p.ty;
        let name = &p.name;
        match &p.arrow_type_override {
            Some(s) => quote! { .param_type(#name, #s) },
            None => quote! {
                .param_type(#name, <#ty as ::vgi_rpc::VgiArrow>::describe_name())
            },
        }
    });
    let param_doc_calls = params.iter().filter(|p| !p.is_ctx).filter_map(|p| {
        let name = &p.name;
        p.doc.as_ref().map(|d| quote! { .param_doc(#name, #d) })
    });
    let param_default_calls = params.iter().filter(|p| !p.is_ctx).filter_map(|p| {
        let name = &p.name;
        p.default
            .as_ref()
            .map(|expr| quote! { .param_default(#name, ::serde_json::json!(#expr)) })
    });

    let call_init_state: TokenStream2 = if is_async {
        quote! {
            ::tokio::task::block_in_place(|| {
                ::tokio::runtime::Handle::current()
                    .block_on(async { inst.#inst_method(#(#param_idents),*).await })
            })?
        }
    } else {
        quote! { inst.#inst_method(#(#param_idents),*)? }
    };

    let header_schema_call: TokenStream2 = if let Some(schema_fn) = meta.header_schema_fn.as_ref() {
        quote! { .header_schema(#schema_fn()) }
    } else if let Some(header_ty) = meta.header.as_ref() {
        quote! {
            .header_schema(::std::sync::Arc::new(::arrow_schema::Schema::new(vec![
                ::arrow_schema::Field::new(
                    "value",
                    <#header_ty as ::vgi_rpc::VgiArrow>::arrow_data_type(),
                    <#header_ty as ::vgi_rpc::VgiArrow>::nullable(),
                )
            ])))
        }
    } else {
        quote! {}
    };

    let registration = quote! {
        {
            #helper_fns

            let __inst = ::std::sync::Arc::clone(&instance);
            server.register(
                ::vgi_rpc::MethodInfo::stream(
                    #method_name,
                    #method_type_variant,
                    #params_schema_fn(),
                    move |req, _ctx| -> ::vgi_rpc::Result<::vgi_rpc::StreamResult> {
                        let inst = ::std::sync::Arc::clone(&__inst);
                        #(#param_reads)*
                        let __state: #state_ty = #call_init_state;
                        #stream_result_ctor
                    },
                )
                #doc_call
                #(#param_type_calls)*
                #(#param_doc_calls)*
                #(#param_default_calls)*
                #header_schema_call
                .with_state_decoder(#decoder_helper),
            );
        }
    };
    Ok(registration)
}
