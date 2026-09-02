//! Stable C ABI for the Arrow-free native VGI Iroh transport.
#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_void, CStr};
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use bytes::Bytes;
use iroh::EndpointId;
use tokio::runtime::{Builder, Runtime};
use tokio_util::sync::CancellationToken;
use vgi_iroh_transport::{
    endpoint_id_hex, ClientEndpoint, DispatchCertainty, EndpointConfig, ErrorCategory, ErrorStage,
    HttpRequest, HttpResponse, RawStream, RelayConfig, RemoteAddr, TransportError,
};
use zeroize::Zeroizing;

const ABI_VERSION: u32 = 1;
const ERROR_MESSAGE_CAPACITY: usize = 512;
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub type vgi_iroh_cancel_check = Option<unsafe extern "C" fn(*mut c_void) -> u8>;

#[repr(C)]
pub struct vgi_iroh_error {
    stage: u32,
    category: u32,
    dispatch_certainty: u32,
    message: [c_char; ERROR_MESSAGE_CAPACITY],
}

#[repr(C)]
pub struct vgi_iroh_endpoint_config {
    abi_version: u32,
    secret_key: *const c_char,
    relay_mode: u32,
    relay_urls: *const *const c_char,
    relay_url_count: usize,
    connect_timeout_ms: u64,
    io_timeout_ms: u64,
}

#[repr(C)]
pub struct vgi_iroh_remote {
    endpoint_id: *const c_char,
    relay_url: *const c_char,
    direct_addresses: *const *const c_char,
    direct_address_count: usize,
}

#[repr(C)]
pub struct vgi_iroh_header {
    name: *const u8,
    name_len: usize,
    value: *const u8,
    value_len: usize,
}

#[repr(C)]
pub struct vgi_iroh_http_request {
    method: *const c_char,
    path: *const c_char,
    headers: *const vgi_iroh_header,
    header_count: usize,
    body: *const u8,
    body_len: usize,
}

pub struct vgi_iroh_endpoint {
    inner: ClientEndpoint,
    runtime: Arc<Runtime>,
}
pub struct vgi_iroh_stream {
    inner: Mutex<RawStream>,
    cancellation: CancellationToken,
    remote_id: EndpointId,
    runtime: Arc<Runtime>,
}
pub struct vgi_iroh_http_response {
    inner: Mutex<HttpResponse>,
    cancellation: CancellationToken,
    status: u16,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    remote_id: EndpointId,
    runtime: Arc<Runtime>,
}

static RUNTIME: OnceLock<Mutex<Weak<Runtime>>> = OnceLock::new();

fn runtime() -> Result<Arc<Runtime>, TransportError> {
    let registry = RUNTIME.get_or_init(|| Mutex::new(Weak::new()));
    let mut registry = registry.lock().map_err(|_| {
        TransportError::new(
            ErrorStage::Internal,
            ErrorCategory::Internal,
            DispatchCertainty::NotApplicable,
            "Iroh runtime registry lock was poisoned",
        )
    })?;
    if let Some(runtime) = registry.upgrade() {
        return Ok(runtime);
    }
    let runtime = Arc::new(
        Builder::new_multi_thread()
            .enable_all()
            .thread_name("vgi-iroh")
            .build()
            .map_err(|error| {
                TransportError::new(
                    ErrorStage::Internal,
                    ErrorCategory::Internal,
                    DispatchCertainty::NotApplicable,
                    format!("failed to initialize Iroh runtime: {error}"),
                )
            })?,
    );
    *registry = Arc::downgrade(&runtime);
    Ok(runtime)
}

fn invalid(message: impl Into<String>) -> TransportError {
    TransportError::new(
        ErrorStage::Config,
        ErrorCategory::InvalidArgument,
        DispatchCertainty::NotApplicable,
        message,
    )
}

async fn host_cancellable<T, F>(
    operation: F,
    cancel_check: vgi_iroh_cancel_check,
    userdata: *mut c_void,
    dispatch: DispatchCertainty,
) -> Result<T, TransportError>
where
    F: Future<Output = Result<T, TransportError>>,
{
    let cancel_check = cancel_check.ok_or_else(|| invalid("cancel_check must not be null"))?;
    tokio::pin!(operation);
    loop {
        if unsafe { cancel_check(userdata) } != 0 {
            return Err(TransportError::new(
                ErrorStage::Cancel,
                ErrorCategory::Cancelled,
                dispatch,
                "Iroh operation cancelled by host",
            ));
        }
        tokio::select! {
            biased;
            result = &mut operation => return result,
            _ = tokio::time::sleep(CANCEL_POLL_INTERVAL) => {}
        }
    }
}

unsafe fn required_ref<'a, T>(value: *const T, name: &str) -> Result<&'a T, TransportError> {
    unsafe { value.as_ref() }.ok_or_else(|| invalid(format!("{name} must not be null")))
}
unsafe fn required_mut<'a, T>(value: *mut T, name: &str) -> Result<&'a mut T, TransportError> {
    unsafe { value.as_mut() }.ok_or_else(|| invalid(format!("{name} must not be null")))
}
unsafe fn c_string(value: *const c_char, name: &str) -> Result<String, TransportError> {
    if value.is_null() {
        return Err(invalid(format!("{name} must not be null")));
    }
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| invalid(format!("{name} must be valid UTF-8")))
}
unsafe fn optional_c_string(
    value: *const c_char,
    name: &str,
) -> Result<Option<String>, TransportError> {
    if value.is_null() {
        Ok(None)
    } else {
        unsafe { c_string(value, name) }.map(Some)
    }
}
unsafe fn string_array(
    value: *const *const c_char,
    count: usize,
    name: &str,
) -> Result<Vec<String>, TransportError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if value.is_null() {
        return Err(invalid(format!(
            "{name} must not be null when count is nonzero"
        )));
    }
    unsafe { slice::from_raw_parts(value, count) }
        .iter()
        .enumerate()
        .map(|(i, value)| unsafe { c_string(*value, &format!("{name}[{i}]")) })
        .collect()
}
unsafe fn byte_slice<'a>(
    value: *const u8,
    count: usize,
    name: &str,
) -> Result<&'a [u8], TransportError> {
    if count == 0 {
        return Ok(&[]);
    }
    if value.is_null() {
        return Err(invalid(format!(
            "{name} must not be null when length is nonzero"
        )));
    }
    Ok(unsafe { slice::from_raw_parts(value, count) })
}

fn write_error(destination: *mut vgi_iroh_error, error: &TransportError) {
    if destination.is_null() {
        return;
    }
    let destination = unsafe { &mut *destination };
    destination.stage = error.stage as u32;
    destination.category = error.category as u32;
    destination.dispatch_certainty = error.dispatch as u32;
    destination.message.fill(0);
    let bytes = error.message.as_bytes();
    let length = bytes.len().min(ERROR_MESSAGE_CAPACITY - 1);
    for (target, source) in destination.message[..length]
        .iter_mut()
        .zip(&bytes[..length])
    {
        *target = *source as c_char;
    }
}

fn ffi<F>(error: *mut vgi_iroh_error, operation: F) -> u32
where
    F: FnOnce() -> Result<(), TransportError>,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => 0,
        Ok(Err(failure)) => {
            write_error(error, &failure);
            1
        }
        Err(_) => {
            write_error(
                error,
                &TransportError::new(
                    ErrorStage::Internal,
                    ErrorCategory::Internal,
                    DispatchCertainty::NotApplicable,
                    "panic contained inside VGI Iroh transport",
                ),
            );
            1
        }
    }
}

fn lock<'a, T>(mutex: &'a Mutex<T>) -> Result<std::sync::MutexGuard<'a, T>, TransportError> {
    mutex.lock().map_err(|_| {
        TransportError::new(
            ErrorStage::Internal,
            ErrorCategory::Internal,
            DispatchCertainty::NotApplicable,
            "Iroh handle lock was poisoned",
        )
    })
}

unsafe fn parse_remote(remote: *const vgi_iroh_remote) -> Result<RemoteAddr, TransportError> {
    let remote = unsafe { required_ref(remote, "remote") }?;
    let id = unsafe { c_string(remote.endpoint_id, "remote.endpoint_id") }?;
    let relay = unsafe { optional_c_string(remote.relay_url, "remote.relay_url") }?;
    let direct = unsafe {
        string_array(
            remote.direct_addresses,
            remote.direct_address_count,
            "remote.direct_addresses",
        )
    }?;
    RemoteAddr::parse(&id, relay.as_deref(), &direct)
}

fn copy_bytes(
    source: &[u8],
    destination: *mut u8,
    capacity: usize,
    required: *mut usize,
    name: &str,
) -> Result<(), TransportError> {
    if !required.is_null() {
        unsafe { *required = source.len() };
    }
    if destination.is_null() && capacity == 0 {
        return if required.is_null() {
            Err(invalid(format!(
                "{name} requires either a buffer or required-length output"
            )))
        } else {
            Ok(())
        };
    }
    if capacity < source.len() {
        return Err(invalid(format!("{name} buffer is too small")));
    }
    if !source.is_empty() {
        if destination.is_null() {
            return Err(invalid(format!("{name} buffer must not be null")));
        }
        unsafe { ptr::copy_nonoverlapping(source.as_ptr(), destination, source.len()) };
    }
    Ok(())
}
fn copy_string(
    source: &str,
    destination: *mut c_char,
    capacity: usize,
    required: *mut usize,
    name: &str,
) -> Result<(), TransportError> {
    if !required.is_null() {
        unsafe { *required = source.len() + 1 };
    }
    if destination.is_null() && capacity == 0 {
        return if required.is_null() {
            Err(invalid(format!(
                "{name} requires either a buffer or required-length output"
            )))
        } else {
            Ok(())
        };
    }
    if capacity < source.len() + 1 {
        return Err(invalid(format!("{name} buffer is too small")));
    }
    if destination.is_null() {
        return Err(invalid(format!("{name} buffer must not be null")));
    }
    unsafe {
        ptr::copy_nonoverlapping(source.as_ptr(), destination.cast::<u8>(), source.len());
        *destination.add(source.len()) = 0;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn vgi_iroh_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_endpoint_create(
    config: *const vgi_iroh_endpoint_config,
    out: *mut *mut vgi_iroh_endpoint,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let config = unsafe { required_ref(config, "config") }?;
        if config.abi_version != ABI_VERSION {
            return Err(invalid(format!(
                "unsupported VGI Iroh ABI version {}",
                config.abi_version
            )));
        }
        let out = unsafe { required_mut(out, "out") }?;
        *out = ptr::null_mut();
        let secret_key = unsafe { optional_c_string(config.secret_key, "config.secret_key") }?
            .map(Zeroizing::new)
            .map(|value| EndpointConfig::parse_secret_key(value.as_str()))
            .transpose()?;
        let relay_values = unsafe {
            string_array(
                config.relay_urls,
                config.relay_url_count,
                "config.relay_urls",
            )
        }?;
        let relays = match config.relay_mode {
            0 if relay_values.is_empty() => RelayConfig::Default,
            1 if relay_values.is_empty() => RelayConfig::Disabled,
            2 => RelayConfig::Custom(EndpointConfig::parse_relays(&relay_values)?),
            0 | 1 => return Err(invalid("relay URLs require custom relay mode")),
            _ => return Err(invalid("invalid relay mode")),
        };
        let endpoint_config = EndpointConfig {
            secret_key,
            relays,
            connect_timeout: Duration::from_millis(config.connect_timeout_ms),
            io_timeout: Duration::from_millis(config.io_timeout_ms),
        };
        let runtime = runtime()?;
        let endpoint = runtime.block_on(ClientEndpoint::bind(endpoint_config))?;
        *out = Box::into_raw(Box::new(vgi_iroh_endpoint {
            inner: endpoint,
            runtime,
        }));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_endpoint_cancel(endpoint: *mut vgi_iroh_endpoint) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(endpoint) = unsafe { endpoint.as_ref() } {
            endpoint.inner.cancel();
        }
    }));
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_endpoint_free(endpoint: *mut vgi_iroh_endpoint) {
    if endpoint.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let endpoint = unsafe { Box::from_raw(endpoint) };
        endpoint.runtime.block_on(endpoint.inner.close());
    }));
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_endpoint_id(
    endpoint: *const vgi_iroh_endpoint,
    buffer: *mut c_char,
    capacity: usize,
    required: *mut usize,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let endpoint = unsafe { required_ref(endpoint, "endpoint") }?;
        copy_string(
            &endpoint_id_hex(endpoint.inner.id()),
            buffer,
            capacity,
            required,
            "endpoint ID",
        )
    })
}

#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_stream_open(
    endpoint: *mut vgi_iroh_endpoint,
    remote: *const vgi_iroh_remote,
    out: *mut *mut vgi_iroh_stream,
    error: *mut vgi_iroh_error,
) -> u32 {
    unsafe { stream_open_impl(endpoint, remote, None, out, ptr::null_mut(), error) }
}

#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_stream_open_timeout(
    endpoint: *mut vgi_iroh_endpoint,
    remote: *const vgi_iroh_remote,
    timeout_ms: u64,
    out: *mut *mut vgi_iroh_stream,
    timed_out: *mut u8,
    error: *mut vgi_iroh_error,
) -> u32 {
    unsafe { stream_open_impl(endpoint, remote, Some(timeout_ms), out, timed_out, error) }
}

#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_stream_open_cancellable(
    endpoint: *mut vgi_iroh_endpoint,
    remote: *const vgi_iroh_remote,
    cancel_check: vgi_iroh_cancel_check,
    userdata: *mut c_void,
    out: *mut *mut vgi_iroh_stream,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let endpoint = unsafe { required_ref(endpoint, "endpoint") }?;
        let out = unsafe { required_mut(out, "out") }?;
        *out = ptr::null_mut();
        let remote = unsafe { parse_remote(remote) }?;
        let remote_id = remote.id;
        let stream = endpoint.runtime.block_on(host_cancellable(
            endpoint.inner.open_raw(&remote),
            cancel_check,
            userdata,
            DispatchCertainty::NotSent,
        ))?;
        *out = make_stream_handle(endpoint, remote_id, stream);
        Ok(())
    })
}

fn make_stream_handle(
    endpoint: &vgi_iroh_endpoint,
    remote_id: EndpointId,
    stream: RawStream,
) -> *mut vgi_iroh_stream {
    let cancellation = stream.cancellation_token();
    Box::into_raw(Box::new(vgi_iroh_stream {
        inner: Mutex::new(stream),
        cancellation,
        remote_id,
        runtime: Arc::clone(&endpoint.runtime),
    }))
}

unsafe fn stream_open_impl(
    endpoint: *mut vgi_iroh_endpoint,
    remote: *const vgi_iroh_remote,
    timeout_ms: Option<u64>,
    out: *mut *mut vgi_iroh_stream,
    timed_out: *mut u8,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let endpoint = unsafe { required_ref(endpoint, "endpoint") }?;
        let out = unsafe { required_mut(out, "out") }?;
        *out = ptr::null_mut();
        if let Some(timeout_ms) = timeout_ms {
            if timeout_ms == 0 {
                return Err(invalid("stream-open timeout must be positive"));
            }
            *unsafe { required_mut(timed_out, "timed_out") }? = 0;
        }
        let remote = unsafe { parse_remote(remote) }?;
        let remote_id = remote.id;
        let result = match timeout_ms {
            Some(timeout_ms) => endpoint.runtime.block_on(
                endpoint
                    .inner
                    .open_raw_with_timeout(&remote, Duration::from_millis(timeout_ms)),
            ),
            None => endpoint.runtime.block_on(endpoint.inner.open_raw(&remote)),
        };
        let stream = match result {
            Ok(stream) => stream,
            Err(failure) if timeout_ms.is_some() && failure.category == ErrorCategory::Timeout => {
                *unsafe { required_mut(timed_out, "timed_out") }? = 1;
                return Ok(());
            }
            Err(failure) => return Err(failure),
        };
        *out = make_stream_handle(endpoint, remote_id, stream);
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_stream_remote_id(
    stream: *const vgi_iroh_stream,
    buffer: *mut c_char,
    capacity: usize,
    required: *mut usize,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let stream = unsafe { required_ref(stream, "stream") }?;
        copy_string(
            &endpoint_id_hex(stream.remote_id),
            buffer,
            capacity,
            required,
            "remote endpoint ID",
        )
    })
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_stream_read(
    stream: *mut vgi_iroh_stream,
    buffer: *mut u8,
    capacity: usize,
    read: *mut usize,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let stream = unsafe { required_ref(stream, "stream") }?;
        let read = unsafe { required_mut(read, "read") }?;
        *read = 0;
        if capacity > 0 && buffer.is_null() {
            return Err(invalid("read buffer must not be null"));
        }
        let output = if capacity == 0 {
            &mut []
        } else {
            unsafe { slice::from_raw_parts_mut(buffer, capacity) }
        };
        *read = stream.runtime.block_on(lock(&stream.inner)?.read(output))?;
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_stream_read_timeout(
    stream: *mut vgi_iroh_stream,
    buffer: *mut u8,
    capacity: usize,
    timeout_ms: u64,
    read: *mut usize,
    timed_out: *mut u8,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let stream = unsafe { required_ref(stream, "stream") }?;
        let read = unsafe { required_mut(read, "read") }?;
        let timed_out = unsafe { required_mut(timed_out, "timed_out") }?;
        *read = 0;
        *timed_out = 0;
        if timeout_ms == 0 {
            return Err(invalid("read timeout must be positive"));
        }
        if capacity > 0 && buffer.is_null() {
            return Err(invalid("read buffer must not be null"));
        }
        let output = if capacity == 0 {
            &mut []
        } else {
            unsafe { slice::from_raw_parts_mut(buffer, capacity) }
        };
        match stream.runtime.block_on(
            lock(&stream.inner)?.read_with_timeout(output, Duration::from_millis(timeout_ms)),
        ) {
            Ok(count) => {
                *read = count;
                Ok(())
            }
            Err(failure) if failure.category == ErrorCategory::Timeout => {
                *timed_out = 1;
                Ok(())
            }
            Err(failure) => Err(failure),
        }
    })
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_stream_write(
    stream: *mut vgi_iroh_stream,
    buffer: *const u8,
    length: usize,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let stream = unsafe { required_ref(stream, "stream") }?;
        let input = unsafe { byte_slice(buffer, length, "write buffer") }?;
        stream
            .runtime
            .block_on(lock(&stream.inner)?.write_all(input))
    })
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_stream_write_timeout(
    stream: *mut vgi_iroh_stream,
    buffer: *const u8,
    length: usize,
    timeout_ms: u64,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        if timeout_ms == 0 {
            return Err(invalid("write timeout must be positive"));
        }
        let stream = unsafe { required_ref(stream, "stream") }?;
        let input = unsafe { byte_slice(buffer, length, "write buffer") }?;
        stream.runtime.block_on(
            lock(&stream.inner)?.write_all_with_timeout(input, Duration::from_millis(timeout_ms)),
        )
    })
}

#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_stream_write_cancellable(
    stream: *mut vgi_iroh_stream,
    buffer: *const u8,
    length: usize,
    cancel_check: vgi_iroh_cancel_check,
    userdata: *mut c_void,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let stream = unsafe { required_ref(stream, "stream") }?;
        let input = unsafe { byte_slice(buffer, length, "write buffer") }?;
        let runtime = Arc::clone(&stream.runtime);
        let mut inner = lock(&stream.inner)?;
        let result = runtime.block_on(host_cancellable(
            inner.write_all(input),
            cancel_check,
            userdata,
            DispatchCertainty::Unknown,
        ));
        if matches!(
            &result,
            Err(failure) if failure.category == ErrorCategory::Cancelled
        ) {
            inner.cancel();
        }
        result
    })
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_stream_finish(
    stream: *mut vgi_iroh_stream,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let stream = unsafe { required_ref(stream, "stream") }?;
        stream.runtime.block_on(lock(&stream.inner)?.finish())
    })
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_stream_cancel(stream: *mut vgi_iroh_stream) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(stream) = unsafe { stream.as_ref() } {
            stream.cancellation.cancel();
        }
    }));
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_stream_free(stream: *mut vgi_iroh_stream) {
    if !stream.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(stream) })));
    }
}

unsafe fn parse_http_request(
    request: *const vgi_iroh_http_request,
) -> Result<HttpRequest, TransportError> {
    let request = unsafe { required_ref(request, "request") }?;
    let method = unsafe { c_string(request.method, "request.method") }?;
    let path = unsafe { c_string(request.path, "request.path") }?;
    let body = Bytes::copy_from_slice(unsafe {
        byte_slice(request.body, request.body_len, "request.body")
    }?);
    let headers = if request.header_count == 0 {
        Vec::new()
    } else {
        if request.headers.is_null() {
            return Err(invalid(
                "request.headers must not be null when count is nonzero",
            ));
        }
        unsafe { slice::from_raw_parts(request.headers, request.header_count) }
            .iter()
            .enumerate()
            .map(|(index, header)| {
                let name = unsafe {
                    byte_slice(
                        header.name,
                        header.name_len,
                        &format!("request.headers[{index}].name"),
                    )
                }?
                .to_vec();
                let value = unsafe {
                    byte_slice(
                        header.value,
                        header.value_len,
                        &format!("request.headers[{index}].value"),
                    )
                }?
                .to_vec();
                Ok((name, value))
            })
            .collect::<Result<Vec<_>, TransportError>>()?
    };
    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_http_request_start(
    endpoint: *mut vgi_iroh_endpoint,
    remote: *const vgi_iroh_remote,
    request: *const vgi_iroh_http_request,
    out: *mut *mut vgi_iroh_http_response,
    error: *mut vgi_iroh_error,
) -> u32 {
    unsafe { http_request_start_impl(endpoint, remote, request, None, out, error) }
}

#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_http_request_start_timeout(
    endpoint: *mut vgi_iroh_endpoint,
    remote: *const vgi_iroh_remote,
    request: *const vgi_iroh_http_request,
    timeout_ms: u64,
    out: *mut *mut vgi_iroh_http_response,
    error: *mut vgi_iroh_error,
) -> u32 {
    unsafe { http_request_start_impl(endpoint, remote, request, Some(timeout_ms), out, error) }
}

#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_http_request_start_cancellable(
    endpoint: *mut vgi_iroh_endpoint,
    remote: *const vgi_iroh_remote,
    request: *const vgi_iroh_http_request,
    cancel_check: vgi_iroh_cancel_check,
    userdata: *mut c_void,
    out: *mut *mut vgi_iroh_http_response,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let endpoint = unsafe { required_ref(endpoint, "endpoint") }?;
        let out = unsafe { required_mut(out, "out") }?;
        *out = ptr::null_mut();
        let remote = unsafe { parse_remote(remote) }?;
        let request = unsafe { parse_http_request(request) }?;
        let response = endpoint.runtime.block_on(host_cancellable(
            endpoint.inner.request(&remote, request),
            cancel_check,
            userdata,
            DispatchCertainty::Unknown,
        ))?;
        *out = make_http_response_handle(endpoint, response);
        Ok(())
    })
}

fn make_http_response_handle(
    endpoint: &vgi_iroh_endpoint,
    response: HttpResponse,
) -> *mut vgi_iroh_http_response {
    let cancellation = response.cancellation_token();
    let status = response.status();
    let headers = response.headers().to_vec();
    let remote_id = response.remote_id();
    Box::into_raw(Box::new(vgi_iroh_http_response {
        inner: Mutex::new(response),
        cancellation,
        status,
        headers,
        remote_id,
        runtime: Arc::clone(&endpoint.runtime),
    }))
}

unsafe fn http_request_start_impl(
    endpoint: *mut vgi_iroh_endpoint,
    remote: *const vgi_iroh_remote,
    request: *const vgi_iroh_http_request,
    timeout_ms: Option<u64>,
    out: *mut *mut vgi_iroh_http_response,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        if timeout_ms == Some(0) {
            return Err(invalid("HTTP response-head timeout must be positive"));
        }
        let endpoint = unsafe { required_ref(endpoint, "endpoint") }?;
        let out = unsafe { required_mut(out, "out") }?;
        *out = ptr::null_mut();
        let remote = unsafe { parse_remote(remote) }?;
        let request = unsafe { parse_http_request(request) }?;
        let response = match timeout_ms {
            Some(timeout_ms) => endpoint
                .runtime
                .block_on(endpoint.inner.request_with_timeout(
                    &remote,
                    request,
                    Duration::from_millis(timeout_ms),
                ))?,
            None => endpoint
                .runtime
                .block_on(endpoint.inner.request(&remote, request))?,
        };
        *out = make_http_response_handle(endpoint, response);
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_http_response_status(
    response: *const vgi_iroh_http_response,
) -> u16 {
    catch_unwind(AssertUnwindSafe(|| {
        unsafe { response.as_ref() }.map_or(0, |r| r.status)
    }))
    .unwrap_or(0)
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_http_response_remote_id(
    response: *const vgi_iroh_http_response,
    buffer: *mut c_char,
    capacity: usize,
    required: *mut usize,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let response = unsafe { required_ref(response, "response") }?;
        copy_string(
            &endpoint_id_hex(response.remote_id),
            buffer,
            capacity,
            required,
            "remote endpoint ID",
        )
    })
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_http_response_header_count(
    response: *const vgi_iroh_http_response,
) -> usize {
    catch_unwind(AssertUnwindSafe(|| {
        unsafe { response.as_ref() }.map_or(0, |r| r.headers.len())
    }))
    .unwrap_or(0)
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_http_response_header(
    response: *const vgi_iroh_http_response,
    index: usize,
    name: *mut u8,
    name_capacity: usize,
    name_required: *mut usize,
    value: *mut u8,
    value_capacity: usize,
    value_required: *mut usize,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let response = unsafe { required_ref(response, "response") }?;
        let (header_name, header_value) = response
            .headers
            .get(index)
            .ok_or_else(|| invalid("HTTP response header index is out of range"))?;
        copy_bytes(
            header_name,
            name,
            name_capacity,
            name_required,
            "HTTP header name",
        )?;
        copy_bytes(
            header_value,
            value,
            value_capacity,
            value_required,
            "HTTP header value",
        )
    })
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_http_response_read(
    response: *mut vgi_iroh_http_response,
    buffer: *mut u8,
    capacity: usize,
    read: *mut usize,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let response = unsafe { required_ref(response, "response") }?;
        let read = unsafe { required_mut(read, "read") }?;
        *read = 0;
        if capacity > 0 && buffer.is_null() {
            return Err(invalid("HTTP read buffer must not be null"));
        }
        let output = if capacity == 0 {
            &mut []
        } else {
            unsafe { slice::from_raw_parts_mut(buffer, capacity) }
        };
        *read = response
            .runtime
            .block_on(lock(&response.inner)?.read(output))?;
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_http_response_read_timeout(
    response: *mut vgi_iroh_http_response,
    buffer: *mut u8,
    capacity: usize,
    timeout_ms: u64,
    read: *mut usize,
    timed_out: *mut u8,
    error: *mut vgi_iroh_error,
) -> u32 {
    ffi(error, || {
        let response = unsafe { required_ref(response, "response") }?;
        let read = unsafe { required_mut(read, "read") }?;
        let timed_out = unsafe { required_mut(timed_out, "timed_out") }?;
        *read = 0;
        *timed_out = 0;
        if timeout_ms == 0 {
            return Err(invalid("HTTP read timeout must be positive"));
        }
        if capacity > 0 && buffer.is_null() {
            return Err(invalid("HTTP read buffer must not be null"));
        }
        let output = if capacity == 0 {
            &mut []
        } else {
            unsafe { slice::from_raw_parts_mut(buffer, capacity) }
        };
        match response.runtime.block_on(
            lock(&response.inner)?.read_with_timeout(output, Duration::from_millis(timeout_ms)),
        ) {
            Ok(count) => {
                *read = count;
                Ok(())
            }
            Err(failure) if failure.category == ErrorCategory::Timeout => {
                *timed_out = 1;
                Ok(())
            }
            Err(failure) => Err(failure),
        }
    })
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_http_response_cancel(response: *mut vgi_iroh_http_response) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(response) = unsafe { response.as_ref() } {
            response.cancellation.cancel();
        }
    }));
}
#[no_mangle]
pub unsafe extern "C" fn vgi_iroh_http_response_free(response: *mut vgi_iroh_http_response) {
    if !response.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            drop(unsafe { Box::from_raw(response) })
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::sync::atomic::{AtomicU8, Ordering};

    use iroh::endpoint::presets;
    use iroh::{Endpoint, RelayMode};
    use vgi_iroh_transport::VGI_IROH_ALPN;

    #[test]
    fn abi_version_is_stable() {
        assert_eq!(vgi_iroh_abi_version(), 1);
        assert_eq!(ErrorStage::Close as u32, 10);
        assert_eq!(ErrorCategory::Authentication as u32, 8);
        assert_eq!(ErrorCategory::ResourceExhausted as u32, 9);
        assert_eq!(ErrorCategory::Internal as u32, 10);
    }

    unsafe extern "C" fn cancel_now(_: *mut c_void) -> u8 {
        1
    }

    unsafe extern "C" fn cancel_from_atomic(userdata: *mut c_void) -> u8 {
        unsafe { &*userdata.cast::<AtomicU8>() }.load(Ordering::Acquire)
    }

    #[test]
    fn host_cancel_callback_is_polled_and_classified() {
        let cancel = AtomicU8::new(0);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(25));
                cancel.store(1, Ordering::Release);
            });
            let failure = runtime()
                .unwrap()
                .block_on(host_cancellable(
                    std::future::pending::<Result<(), TransportError>>(),
                    Some(cancel_from_atomic),
                    (&cancel as *const AtomicU8).cast_mut().cast::<c_void>(),
                    DispatchCertainty::Unknown,
                ))
                .unwrap_err();
            assert_eq!(failure.stage, ErrorStage::Cancel);
            assert_eq!(failure.category, ErrorCategory::Cancelled);
            assert_eq!(failure.dispatch, DispatchCertainty::Unknown);
        });
    }

    #[test]
    fn rejects_wrong_abi_without_panicking() {
        let config = vgi_iroh_endpoint_config {
            abi_version: 99,
            secret_key: ptr::null(),
            relay_mode: 1,
            relay_urls: ptr::null(),
            relay_url_count: 0,
            connect_timeout_ms: 100,
            io_timeout_ms: 100,
        };
        let mut output = ptr::null_mut();
        let mut error = vgi_iroh_error {
            stage: 0,
            category: 0,
            dispatch_certainty: 0,
            message: [0; ERROR_MESSAGE_CAPACITY],
        };
        let result = unsafe { vgi_iroh_endpoint_create(&config, &mut output, &mut error) };
        assert_eq!(result, 1);
        assert!(output.is_null());
        assert_eq!(error.category, ErrorCategory::InvalidArgument as u32);
    }

    #[test]
    fn c_abi_raw_loopback_round_trips_and_exposes_id() {
        let test_runtime = runtime().unwrap();
        let server = test_runtime
            .block_on(
                Endpoint::builder(presets::N0)
                    .alpns(vec![VGI_IROH_ALPN.to_vec()])
                    .relay_mode(RelayMode::Disabled)
                    .bind(),
            )
            .unwrap();
        let server_id = CString::new(endpoint_id_hex(server.id())).unwrap();
        let direct = server
            .addr()
            .ip_addrs()
            .map(|address| CString::new(address.to_string()).unwrap())
            .collect::<Vec<_>>();
        let direct_pointers = direct
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        let (response_ready_tx, response_ready_rx) = tokio::sync::oneshot::channel();
        let (response_read_tx, response_read_rx) = tokio::sync::oneshot::channel();
        let server_task = test_runtime.spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let mut request = [0_u8; 4];
            recv.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            send.write_all(b"pong").await.unwrap();
            send.finish().unwrap();
            response_ready_tx.send(()).unwrap();
            response_read_rx.await.unwrap();
        });

        let config = vgi_iroh_endpoint_config {
            abi_version: ABI_VERSION,
            secret_key: ptr::null(),
            relay_mode: 1,
            relay_urls: ptr::null(),
            relay_url_count: 0,
            connect_timeout_ms: 5_000,
            io_timeout_ms: 5_000,
        };
        let remote = vgi_iroh_remote {
            endpoint_id: server_id.as_ptr(),
            relay_url: ptr::null(),
            direct_addresses: direct_pointers.as_ptr(),
            direct_address_count: direct_pointers.len(),
        };
        let mut error = vgi_iroh_error {
            stage: 0,
            category: 0,
            dispatch_certainty: 0,
            message: [0; ERROR_MESSAGE_CAPACITY],
        };
        let mut endpoint = ptr::null_mut();
        assert_eq!(
            unsafe { vgi_iroh_endpoint_create(&config, &mut endpoint, &mut error) },
            0
        );
        let mut local_id = [0_i8; 65];
        let mut required = 0;
        assert_eq!(
            unsafe {
                vgi_iroh_endpoint_id(
                    endpoint,
                    local_id.as_mut_ptr(),
                    local_id.len(),
                    &mut required,
                    &mut error,
                )
            },
            0
        );
        assert_eq!(required, 65);

        let mut cancelled_stream = ptr::null_mut();
        assert_eq!(
            unsafe {
                vgi_iroh_stream_open_cancellable(
                    endpoint,
                    &remote,
                    Some(cancel_now),
                    ptr::null_mut(),
                    &mut cancelled_stream,
                    &mut error,
                )
            },
            1
        );
        assert!(cancelled_stream.is_null());
        assert_eq!(error.stage, ErrorStage::Cancel as u32);
        assert_eq!(error.category, ErrorCategory::Cancelled as u32);
        assert_eq!(error.dispatch_certainty, DispatchCertainty::NotSent as u32);

        let method = CString::new("OPTIONS").unwrap();
        let path = CString::new("/").unwrap();
        let request = vgi_iroh_http_request {
            method: method.as_ptr(),
            path: path.as_ptr(),
            headers: ptr::null(),
            header_count: 0,
            body: ptr::null(),
            body_len: 0,
        };
        let mut cancelled_response = ptr::null_mut();
        assert_eq!(
            unsafe {
                vgi_iroh_http_request_start_cancellable(
                    endpoint,
                    &remote,
                    &request,
                    Some(cancel_now),
                    ptr::null_mut(),
                    &mut cancelled_response,
                    &mut error,
                )
            },
            1
        );
        assert!(cancelled_response.is_null());
        assert_eq!(error.stage, ErrorStage::Cancel as u32);
        assert_eq!(error.category, ErrorCategory::Cancelled as u32);
        assert_eq!(error.dispatch_certainty, DispatchCertainty::Unknown as u32);

        let mut stream = ptr::null_mut();
        assert_eq!(
            unsafe { vgi_iroh_stream_open(endpoint, &remote, &mut stream, &mut error) },
            0
        );
        let mut poll_buffer = [0_u8; 1];
        let mut poll_read = 99;
        let mut timed_out = 0;
        assert_eq!(
            unsafe {
                vgi_iroh_stream_read_timeout(
                    stream,
                    poll_buffer.as_mut_ptr(),
                    poll_buffer.len(),
                    1,
                    &mut poll_read,
                    &mut timed_out,
                    &mut error,
                )
            },
            0
        );
        assert_eq!(poll_read, 0);
        assert_eq!(timed_out, 1);
        assert_eq!(
            unsafe { vgi_iroh_stream_write(stream, b"ping".as_ptr(), 4, &mut error) },
            0
        );
        assert_eq!(unsafe { vgi_iroh_stream_finish(stream, &mut error) }, 0);
        test_runtime
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(5), response_ready_rx).await
            })
            .expect("server response deadline")
            .expect("server response task");
        let mut output = [0_u8; 4];
        let mut read = 0;
        let read_result = unsafe {
            vgi_iroh_stream_read(
                stream,
                output.as_mut_ptr(),
                output.len(),
                &mut read,
                &mut error,
            )
        };
        let error_message = unsafe { CStr::from_ptr(error.message.as_ptr()) }.to_string_lossy();
        assert_eq!(read_result, 0, "{error_message}");
        assert_eq!(read, 4);
        assert_eq!(&output, b"pong");

        assert_eq!(
            unsafe {
                vgi_iroh_stream_write_cancellable(
                    stream,
                    b"ignored".as_ptr(),
                    7,
                    Some(cancel_now),
                    ptr::null_mut(),
                    &mut error,
                )
            },
            1
        );
        assert_eq!(error.stage, ErrorStage::Cancel as u32);
        assert_eq!(error.category, ErrorCategory::Cancelled as u32);
        assert_eq!(error.dispatch_certainty, DispatchCertainty::Unknown as u32);
        response_read_tx.send(()).unwrap();

        unsafe {
            vgi_iroh_stream_free(stream);
            vgi_iroh_endpoint_free(endpoint);
        }
        test_runtime.block_on(server_task).unwrap();
    }
}
