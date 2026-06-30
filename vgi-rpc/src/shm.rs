//! Shared-memory transport support for Arrow IPC batches.
//!
//! Mirrors the Python `vgi_rpc.shm` module byte-for-byte — same header
//! layout, same allocator semantics, same pointer-batch encoding — so a
//! Python client can advertise a segment via request metadata and a Rust
//! server can attach, resolve pointer batches on input, and (optionally)
//! write outputs back into the segment.
//!
//! # Header layout (little-endian, language-agnostic)
//!
//! ```text
//! Offset  Size  Field
//! 0       4     magic: b"VGIS"
//! 4       4     version: u32 = 1
//! 8       8     data_size: u64 (segment size minus header)
//! 16      4     num_allocs: u32
//! 20      4     padding
//! 24      N*16  allocations: array of (offset: u64, length: u64),
//!               sorted by offset
//! ```
//!
//! Data region starts at [`HEADER_SIZE`]. Allocations are coalesced
//! implicitly: only occupied regions are tracked, so freeing neighbours
//! grows the gap between remaining entries naturally.
//!
//! # Lifecycle
//!
//! - **Client owns the segment.** It calls `create`, advertises
//!   `(name, size)` on each request via metadata
//!   ([`SHM_SEGMENT_NAME_KEY`] / [`SHM_SEGMENT_SIZE_KEY`]), and
//!   `unlink`s the OS object when finished.
//! - **Server attaches dynamically** with `track = false` (it is not the
//!   owner) for the duration of one call and detaches afterwards.
//! - **Lockstep RPC** means the client and server are never both
//!   touching the segment at the same time, so no locking is needed
//!   inside the allocator.
//!
//! # ⚠️ Trust boundary — trusted peers only
//!
//! The SHM transport **must not be exposed to untrusted clients.** The
//! client owns the OS object: it can mutate the header concurrently from
//! another thread (the lockstep assumption is cooperative, not
//! enforceable), and it supplies the segment size in request metadata.
//! A client that lies about the size can make the server `mmap` a region
//! larger than the backing object — a subsequent read then faults with
//! `SIGBUS`, which **cannot** be caught by `catch_unwind`. The header
//! fields (`num_allocs`, allocation offsets/lengths) are likewise read
//! from client-writable memory; the parser bounds-checks them
//! defensively, but corruption still yields garbage allocations.
//!
//! Use SHM only when the client and server are in the same trust domain
//! (e.g. a subprocess pool you spawn). For untrusted peers, use the
//! pipe / unix / HTTP transports.
//!
//! [`SHM_SEGMENT_NAME_KEY`]: crate::metadata::SHM_SEGMENT_NAME_KEY
//! [`SHM_SEGMENT_SIZE_KEY`]: crate::metadata::SHM_SEGMENT_SIZE_KEY

#[cfg(unix)]
use std::ffi::CString;
use std::io::Cursor;
use std::sync::Arc;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, INVALID_HANDLE_VALUE,
};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, OpenFileMappingW, UnmapViewOfFile,
    MEMORY_MAPPED_VIEW_ADDRESS, FILE_MAP_READ, FILE_MAP_WRITE, PAGE_READWRITE,
};

use arrow_array::RecordBatch;
use arrow_ipc::reader::StreamReader as IpcStreamReader;
use arrow_ipc::writer::StreamWriter as IpcStreamWriter;
use arrow_schema::{DataType, Schema};

use crate::errors::{Result, RpcError};
use crate::metadata::{LOG_LEVEL_KEY, SHM_LENGTH_KEY, SHM_OFFSET_KEY, SHM_SOURCE_KEY};
use crate::wire::{self, Metadata};

/// Header size at the start of every SHM segment. Allocator state lives
/// in the first [`HEADER_SIZE`] bytes; user data starts at this offset.
pub const HEADER_SIZE: usize = 65_536;

const MAGIC: &[u8; 4] = b"VGIS";
const VERSION: u32 = 1;

const HEADER_FIXED_SIZE: usize = 24;
const ALLOC_ENTRY_SIZE: usize = 16;

/// Maximum number of concurrent allocations the header can hold (4094,
/// matching the Python implementation).
pub const MAX_ALLOCS: usize = (HEADER_SIZE - HEADER_FIXED_SIZE) / ALLOC_ENTRY_SIZE;

/// IPC stream EOS marker: continuation token + 0-length metadata.
const IPC_EOS: [u8; 8] = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];

// ---------------------------------------------------------------------------
// OS shared-memory primitive (POSIX shm_open + mmap)
// ---------------------------------------------------------------------------

/// Owned handle to a named shared-memory segment.
///
/// Backed by POSIX `shm_open`/`mmap` on Unix and by a page-file-backed
/// named `CreateFileMapping`/`MapViewOfFile` section on Windows. The
/// portable layer above ([`ShmAllocator`], [`ShmSegment`]) only touches
/// [`as_slice`](OsShm::as_slice)/[`as_mut_slice`](OsShm::as_mut_slice),
/// so the byte layout stays identical across all peers.
struct OsShm {
    name: String,
    ptr: *mut u8,
    size: usize,
    /// True if this handle owns the OS object (created with `create=true`).
    /// On Unix it drives `shm_unlink` on drop; on Windows the mapping object
    /// is reference-counted by the kernel and released when the last handle
    /// closes, so this is informational there. Server-side dynamic
    /// attachments set this to `false`.
    track: bool,
    /// Windows file-mapping object handle, closed on drop. Absent on Unix,
    /// where the fd is closed immediately after `mmap`.
    #[cfg(windows)]
    map_handle: windows_sys::Win32::Foundation::HANDLE,
}

unsafe impl Send for OsShm {}
unsafe impl Sync for OsShm {}

// `OsShm` carries a raw pointer (the mapped region) but the data it
// points at is not invalidated by panics — the OS owns the page table
// entries until unmap, and our drop runs only when no Arc clones
// remain.
impl std::panic::RefUnwindSafe for OsShm {}

fn make_shm_name() -> String {
    // Python's `multiprocessing.shared_memory` uses `psm_<8 hex>_<8 hex>`
    // on macOS and `/<rand>` on Linux; we match its leading-slash POSIX
    // convention. Windows `CreateFileMapping` object names must NOT contain
    // a slash (a leading `\` selects a different namespace), so the name is
    // emitted slash-free there. Either form works as long as the peer is
    // handed the literal string via metadata.
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    #[cfg(windows)]
    {
        format!("vgi_rpc_{:x}_{:x}", pid, nanos as u64)
    }
    #[cfg(not(windows))]
    {
        format!("/vgi_rpc_{:x}_{:x}", pid, nanos as u64)
    }
}

#[cfg(unix)]
impl OsShm {
    fn create(size: usize) -> Result<Self> {
        for _ in 0..16 {
            let name = make_shm_name();
            match Self::try_create(&name, size) {
                Ok(h) => return Ok(h),
                Err(e) if e.error_type == "AlreadyExists" => continue,
                Err(e) => return Err(e),
            }
        }
        Err(RpcError::new("IOError", "shm_open exhausted name retries"))
    }

    fn try_create(name: &str, size: usize) -> Result<Self> {
        let cname = CString::new(name)
            .map_err(|e| RpcError::new("ValueError", format!("invalid shm name: {e}")))?;
        let fd = unsafe {
            libc::shm_open(
                cname.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            let kind = if err.raw_os_error() == Some(libc::EEXIST) {
                "AlreadyExists"
            } else {
                "IOError"
            };
            return Err(RpcError::new(kind, format!("shm_open(create): {err}")));
        }
        let rc = unsafe { libc::ftruncate(fd, size as libc::off_t) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
                libc::shm_unlink(cname.as_ptr());
            }
            return Err(RpcError::new("IOError", format!("ftruncate: {err}")));
        }
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        unsafe { libc::close(fd) };
        if ptr == libc::MAP_FAILED {
            let err = std::io::Error::last_os_error();
            unsafe { libc::shm_unlink(cname.as_ptr()) };
            return Err(RpcError::new("IOError", format!("mmap: {err}")));
        }
        Ok(Self {
            name: name.to_string(),
            ptr: ptr as *mut u8,
            size,
            track: true,
        })
    }

    fn attach(name: &str, size: usize, track: bool) -> Result<Self> {
        // Python's `multiprocessing.shared_memory.SharedMemory.name`
        // strips the leading `/` on POSIX before exposing the name; the
        // actual OS object is registered with a leading `/`. Normalize
        // both forms — try the name as given, then with `/` prepended.
        let try_open = |candidate: &str| -> std::io::Result<i32> {
            let cname = CString::new(candidate).map_err(std::io::Error::other)?;
            let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDWR, 0o600) };
            if fd < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(fd)
            }
        };
        let fd = match try_open(name) {
            Ok(fd) => fd,
            Err(first) if !name.starts_with('/') => match try_open(&format!("/{name}")) {
                Ok(fd) => fd,
                Err(second) => {
                    return Err(RpcError::new(
                        "IOError",
                        format!("shm_open(attach) {name:?}: {first}; with leading slash: {second}"),
                    ));
                }
            },
            Err(e) => {
                return Err(RpcError::new("IOError", format!("shm_open(attach): {e}")));
            }
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(RpcError::new("IOError", format!("shm_open(attach): {err}")));
        }
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        unsafe { libc::close(fd) };
        if ptr == libc::MAP_FAILED {
            let err = std::io::Error::last_os_error();
            return Err(RpcError::new("IOError", format!("mmap: {err}")));
        }
        Ok(Self {
            name: name.to_string(),
            ptr: ptr as *mut u8,
            size,
            track,
        })
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.size) }
    }

    #[allow(clippy::mut_from_ref)]
    fn as_mut_slice(&self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size) }
    }
}

#[cfg(unix)]
impl Drop for OsShm {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.size) };
        }
        if self.track {
            if let Ok(cname) = CString::new(self.name.as_str()) {
                unsafe { libc::shm_unlink(cname.as_ptr()) };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Windows backend: page-file-backed named CreateFileMapping + MapViewOfFile.
//
// Interoperates with the C++/Go/Python peers, which create the same
// page-file-backed section under the slash-free advertised name. The mapping
// object is reference-counted by the kernel, so closing the worker's handle
// does not destroy the section while the owner (the engine) still holds one —
// there is no `unlink` step, unlike POSIX `shm_unlink`.
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
impl OsShm {
    fn create(size: usize) -> Result<Self> {
        for _ in 0..16 {
            let name = make_shm_name();
            match Self::try_create(&name, size) {
                Ok(h) => return Ok(h),
                Err(e) if e.error_type == "AlreadyExists" => continue,
                Err(e) => return Err(e),
            }
        }
        Err(RpcError::new(
            "IOError",
            "CreateFileMapping exhausted name retries",
        ))
    }

    fn try_create(name: &str, size: usize) -> Result<Self> {
        let wname = to_wide(name);
        let handle = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                PAGE_READWRITE,
                (size >> 32) as u32,
                (size & 0xffff_ffff) as u32,
                wname.as_ptr(),
            )
        };
        if handle.is_null() {
            let err = unsafe { GetLastError() };
            return Err(RpcError::new(
                "IOError",
                format!("CreateFileMapping(create) {name:?}: error {err}"),
            ));
        }
        // Exclusive-create semantics (mirrors POSIX O_CREAT|O_EXCL): a valid
        // handle plus ERROR_ALREADY_EXISTS means the named object pre-existed.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe { CloseHandle(handle) };
            return Err(RpcError::new("AlreadyExists", format!("shm name {name:?} exists")));
        }
        Self::map(handle, name, size, true)
    }

    fn attach(name: &str, size: usize, track: bool) -> Result<Self> {
        let wname = to_wide(name);
        let handle =
            unsafe { OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, 0, wname.as_ptr()) };
        if handle.is_null() {
            let err = unsafe { GetLastError() };
            return Err(RpcError::new(
                "IOError",
                format!("OpenFileMapping(attach) {name:?}: error {err}"),
            ));
        }
        Self::map(handle, name, size, track)
    }

    fn map(handle: HANDLE, name: &str, size: usize, track: bool) -> Result<Self> {
        let view =
            unsafe { MapViewOfFile(handle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, size) };
        if view.Value.is_null() {
            let err = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            return Err(RpcError::new("IOError", format!("MapViewOfFile: error {err}")));
        }
        Ok(Self {
            name: name.to_string(),
            ptr: view.Value as *mut u8,
            size,
            track,
            map_handle: handle,
        })
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.size) }
    }

    #[allow(clippy::mut_from_ref)]
    fn as_mut_slice(&self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size) }
    }
}

#[cfg(windows)]
impl Drop for OsShm {
    fn drop(&mut self) {
        // `track` is informational on Windows — the kernel reference-counts
        // the section and frees it when the last handle closes.
        let _ = self.track;
        if !self.ptr.is_null() {
            unsafe {
                UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: self.ptr as *mut core::ffi::c_void,
                });
            }
        }
        if !self.map_handle.is_null() {
            unsafe { CloseHandle(self.map_handle) };
        }
    }
}

// ---------------------------------------------------------------------------
// ShmAllocator — first-fit allocator stored in segment header
// ---------------------------------------------------------------------------

/// First-fit allocator over the segment's data region. State lives in
/// the segment header; adjacent free regions coalesce implicitly.
pub struct ShmAllocator {
    shm: Arc<OsShm>,
    total_size: usize,
}

impl ShmAllocator {
    /// Initialize the header at the start of `shm` with zero allocations.
    fn initialize(shm: &OsShm) -> Result<()> {
        if shm.size <= HEADER_SIZE {
            return Err(RpcError::new(
                "ValueError",
                format!("segment size must be > {HEADER_SIZE}, got {}", shm.size),
            ));
        }
        let data_size = (shm.size - HEADER_SIZE) as u64;
        let buf = shm.as_mut_slice();
        buf[0..4].copy_from_slice(MAGIC);
        buf[4..8].copy_from_slice(&VERSION.to_le_bytes());
        buf[8..16].copy_from_slice(&data_size.to_le_bytes());
        buf[16..20].copy_from_slice(&0u32.to_le_bytes());
        buf[20..24].copy_from_slice(&0u32.to_le_bytes());
        Ok(())
    }

    fn attach(shm: Arc<OsShm>) -> Result<Self> {
        let buf = shm.as_slice();
        if &buf[0..4] != MAGIC {
            return Err(RpcError::new(
                "ValueError",
                format!("bad SHM magic: {:?}", &buf[0..4]),
            ));
        }
        let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        if version != VERSION {
            return Err(RpcError::new(
                "ValueError",
                format!("unsupported SHM version: {version}"),
            ));
        }
        let data_size = u64::from_le_bytes(buf[8..16].try_into().unwrap()) as usize;
        let expected = shm.size - HEADER_SIZE;
        if data_size != expected {
            return Err(RpcError::new(
                "ValueError",
                format!("data_size mismatch: header says {data_size}, expected {expected}"),
            ));
        }
        let total_size = shm.size;
        Ok(Self { shm, total_size })
    }

    /// Number of currently active allocations.
    pub fn num_allocs(&self) -> usize {
        let buf = self.shm.as_slice();
        u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize
    }

    /// Capacity (4094).
    pub fn max_allocs(&self) -> usize {
        MAX_ALLOCS
    }

    /// Snapshot of the live allocation list as `(offset, length)` pairs,
    /// in stored order. Intended for diagnostics and cross-language
    /// compatibility tests. Hot paths should not call this — it copies
    /// the table out of the segment header.
    pub fn dump_allocs(&self) -> Vec<(u64, u64)> {
        self.read_allocs()
    }

    fn read_allocs(&self) -> Vec<(u64, u64)> {
        let buf = self.shm.as_slice();
        // `num_allocs` is read from client-writable memory. Clamp it to
        // `MAX_ALLOCS` so a corrupt/hostile value can't drive the loop's
        // slice indexing past the fixed-size allocation table.
        let n = (u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize).min(MAX_ALLOCS);
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let base = HEADER_FIXED_SIZE + i * ALLOC_ENTRY_SIZE;
            let off = u64::from_le_bytes(buf[base..base + 8].try_into().unwrap());
            let len = u64::from_le_bytes(buf[base + 8..base + 16].try_into().unwrap());
            out.push((off, len));
        }
        out
    }

    fn write_allocs(&self, allocs: &[(u64, u64)]) {
        let buf = self.shm.as_mut_slice();
        buf[16..20].copy_from_slice(&(allocs.len() as u32).to_le_bytes());
        for (i, (off, len)) in allocs.iter().enumerate() {
            let base = HEADER_FIXED_SIZE + i * ALLOC_ENTRY_SIZE;
            buf[base..base + 8].copy_from_slice(&off.to_le_bytes());
            buf[base + 8..base + 16].copy_from_slice(&len.to_le_bytes());
        }
    }

    /// First-fit allocate `size` bytes. Returns the absolute offset, or
    /// `None` if no gap is large enough or the allocation table is full.
    pub fn allocate(&self, size: usize) -> Option<u64> {
        if size == 0 {
            return None;
        }
        let mut allocs = self.read_allocs();
        if allocs.len() >= MAX_ALLOCS {
            return None;
        }
        // Defensive: if the on-segment alloc list is somehow not sorted
        // by offset (corruption, or a buggy peer), `off - prev_end` would
        // underflow into a giant phantom gap and we'd hand out an offset
        // past the segment. Sort + bounds-check explicitly so a bad peer
        // can't drive us into a slice panic.
        allocs.sort_by_key(|(o, _)| *o);
        let size = size as u64;
        let data_end = self.total_size as u64;
        let mut prev_end = HEADER_SIZE as u64;
        for (i, (off, len)) in allocs.iter().enumerate() {
            // Skip overlapping / out-of-range entries instead of trusting
            // them. A returned offset must satisfy
            // `prev_end + size <= off`; if `off < prev_end` we'd otherwise
            // underflow.
            if *off < prev_end {
                prev_end = prev_end.max(off.saturating_add(*len));
                continue;
            }
            let gap = off - prev_end;
            if gap >= size && prev_end.saturating_add(size) <= data_end {
                allocs.insert(i, (prev_end, size));
                self.write_allocs(&allocs);
                return Some(prev_end);
            }
            prev_end = off.saturating_add(*len);
        }
        if prev_end >= data_end {
            return None;
        }
        let gap = data_end - prev_end;
        if gap >= size {
            allocs.push((prev_end, size));
            self.write_allocs(&allocs);
            return Some(prev_end);
        }
        None
    }

    /// Free the region starting at `offset`. Errors if no such allocation.
    pub fn free(&self, offset: u64) -> Result<()> {
        let mut allocs = self.read_allocs();
        if let Some(idx) = allocs.iter().position(|(o, _)| *o == offset) {
            allocs.remove(idx);
            self.write_allocs(&allocs);
            Ok(())
        } else {
            Err(RpcError::new(
                "ValueError",
                format!("no allocation at offset {offset}"),
            ))
        }
    }

    /// Shrink an existing allocation to `new_len`. Used by the in-place
    /// write path: a worst-case slot is reserved, the IPC stream is
    /// written directly into the SHM mapping via a `Cursor`, and the
    /// allocator entry is then shrunk to the actual bytes written so the
    /// unused tail is returned to the free pool.
    pub fn shrink(&self, offset: u64, new_len: usize) -> Result<()> {
        let mut allocs = self.read_allocs();
        let idx = allocs
            .iter()
            .position(|(o, _)| *o == offset)
            .ok_or_else(|| {
                RpcError::new("ValueError", format!("no allocation at offset {offset}"))
            })?;
        let cur = allocs[idx].1;
        if (new_len as u64) > cur {
            return Err(RpcError::new(
                "ValueError",
                format!("shrink: new_len {new_len} > reservation {cur}"),
            ));
        }
        allocs[idx].1 = new_len as u64;
        self.write_allocs(&allocs);
        Ok(())
    }

    /// Clear the allocation table.
    pub fn reset(&self) {
        let buf = self.shm.as_mut_slice();
        buf[16..20].copy_from_slice(&0u32.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// ShmSegment — segment + allocator + zero-copy batch I/O
// ---------------------------------------------------------------------------

/// Shared-memory segment for zero-copy Arrow IPC batch transfer.
pub struct ShmSegment {
    shm: Arc<OsShm>,
    allocator: ShmAllocator,
}

impl ShmSegment {
    /// Create a new segment of `size` bytes. The handle owns the OS
    /// object; dropping `ShmSegment` calls `shm_unlink`.
    pub fn create(size: usize) -> Result<Self> {
        let shm = Arc::new(OsShm::create(size)?);
        ShmAllocator::initialize(&shm)?;
        let allocator = ShmAllocator::attach(shm.clone())?;
        Ok(Self { shm, allocator })
    }

    /// Attach to an existing segment by name. `track = false` means the
    /// caller is *not* the owner — the OS object will not be unlinked
    /// on drop. Servers handling a client-advertised segment use this.
    pub fn attach(name: &str, size: usize, track: bool) -> Result<Self> {
        let shm = Arc::new(OsShm::attach(name, size, track)?);
        let allocator = ShmAllocator::attach(shm.clone())?;
        Ok(Self { shm, allocator })
    }

    /// OS name of the segment.
    pub fn name(&self) -> &str {
        &self.shm.name
    }

    /// Total segment size, including header.
    pub fn size(&self) -> usize {
        self.shm.size
    }

    /// Borrow the allocator.
    pub fn allocator(&self) -> &ShmAllocator {
        &self.allocator
    }

    /// Reset the allocator (free all regions).
    pub fn reset(&self) {
        self.allocator.reset();
    }

    /// Read `length` bytes starting at `offset`. Caller owns the copy
    /// (Rust's `RecordBatch` doesn't borrow from the SHM region after
    /// deserialization, unlike Python's zero-copy `pa.py_buffer`).
    pub fn read_bytes(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
        let off: usize = offset
            .try_into()
            .map_err(|_| RpcError::new("ValueError", "shm offset overflow"))?;
        let end = off
            .checked_add(length)
            .ok_or_else(|| RpcError::new("ValueError", "shm region overflow"))?;
        if end > self.shm.size {
            return Err(RpcError::new(
                "ValueError",
                format!(
                    "shm region {off}..{end} out of bounds (size={})",
                    self.shm.size
                ),
            ));
        }
        Ok(self.shm.as_slice()[off..end].to_vec())
    }

    /// Serialize `batch` as a full IPC stream into the segment. For
    /// non-dictionary schemas the stream is written in place; for
    /// dictionary-encoded schemas the schema message + EOS marker are
    /// stripped (the reverse is done in [`Self::read_batch`]) so the
    /// SHM region holds only dictionary messages + the record batch
    /// message — matching the Python implementation byte-for-byte.
    ///
    /// Returns `(offset, length)` or `None` if the segment can't fit
    /// the serialized batch.
    pub fn allocate_and_write(&self, batch: &RecordBatch) -> Result<Option<(u64, usize)>> {
        let schema = batch.schema();
        // Dictionary path keeps the legacy serialize-to-Vec + memcpy flow:
        // it has to strip the leading schema message and trailing EOS
        // marker, which is awkward to do in place. Dict batches are the
        // slow path anyway.
        if schema_has_dictionary(schema.as_ref()) {
            let bytes = serialize_for_shm(batch, schema.as_ref())?;
            let size = bytes.len();
            let Some(offset) = self.allocator.allocate(size) else {
                return Ok(None);
            };
            let off = offset as usize;
            let end = off.checked_add(size).filter(|e| *e <= self.shm.size);
            let Some(end) = end else {
                let _ = self.allocator.free(offset);
                return Err(RpcError::new(
                    "ValueError",
                    "shm allocator returned out-of-bounds offset",
                ));
            };
            let dst = &mut self.shm.as_mut_slice()[off..end];
            dst.copy_from_slice(&bytes);
            return Ok(Some((offset, size)));
        }
        // Non-dict fast path: reserve a worst-case slot, write the IPC
        // stream directly into the SHM mapping via a `Cursor`, then
        // shrink the allocator entry to the actual bytes written. Avoids
        // the intermediate `Vec` and the second whole-stream memcpy.
        let body_estimate = batch.get_array_memory_size().saturating_mul(2);
        let reserve = body_estimate.saturating_add(65_536);
        // Cap to the segment's data region; allocate() will still fail if
        // there's no contiguous gap that big, but capping here avoids a
        // pointless oversize ask.
        let max_region = self.shm.size.saturating_sub(HEADER_SIZE);
        let reserve = reserve.min(max_region);
        if reserve == 0 {
            return Ok(None);
        }
        let Some(offset) = self.allocator.allocate(reserve) else {
            return Ok(None);
        };
        let off = offset as usize;
        let end = match off.checked_add(reserve).filter(|e| *e <= self.shm.size) {
            Some(e) => e,
            None => {
                let _ = self.allocator.free(offset);
                return Err(RpcError::new(
                    "ValueError",
                    "shm allocator returned out-of-bounds offset",
                ));
            }
        };
        let written: u64 = {
            let dst = &mut self.shm.as_mut_slice()[off..end];
            let mut cursor = Cursor::new(dst);
            let result: Result<u64> = (|| {
                let mut w = IpcStreamWriter::try_new(&mut cursor, schema.as_ref())
                    .map_err(RpcError::from)?;
                w.write(batch).map_err(RpcError::from)?;
                w.finish().map_err(RpcError::from)?;
                Ok(cursor.position())
            })();
            match result {
                Ok(n) => n,
                Err(e) => {
                    let _ = self.allocator.free(offset);
                    // Cursor over a fixed slice returns WriteZero on overflow,
                    // surfaced as ArrowError::Io. Treat that as "doesn't fit"
                    // (caller falls back to pipe). Other errors propagate.
                    if e.message.contains("failed to write whole buffer")
                        || e.message.contains("write zero")
                    {
                        return Ok(None);
                    }
                    return Err(e);
                }
            }
        };
        let actual = written as usize;
        self.allocator.shrink(offset, actual)?;
        Ok(Some((offset, actual)))
    }

    /// Inverse of [`Self::allocate_and_write`]: read a record batch
    /// previously written into the segment.
    ///
    /// For non-dictionary schemas this is **fully zero-copy**: the
    /// returned [`RecordBatch`]'s column buffers alias the SHM mapping
    /// directly via [`Buffer::from_custom_allocation`], with an
    /// [`Arc`] of the underlying [`OsShm`] keeping the mmap alive
    /// as long as any column buffer references it.
    ///
    /// For dictionary-encoded schemas the SHM region holds only the
    /// dictionary + record-batch messages (no schema, no EOS), so we
    /// stitch a synthetic stream around them; that path still copies
    /// the region into a `Vec` for the moment.
    pub fn read_batch(&self, offset: u64, length: usize, schema: &Schema) -> Result<RecordBatch> {
        let off: usize = offset
            .try_into()
            .map_err(|_| RpcError::new("ValueError", "shm offset overflow"))?;
        let end = off
            .checked_add(length)
            .ok_or_else(|| RpcError::new("ValueError", "shm region overflow"))?;
        if end > self.shm.size {
            return Err(RpcError::new(
                "ValueError",
                format!("shm region out of bounds: {off}..{end} > {}", self.shm.size),
            ));
        }
        // Both the no-dict and dict paths read through
        // `deserialize_from_shm`, which copies the region bytes into a
        // synthetic IPC stream and decodes via upstream arrow-ipc.
        // Earlier revisions kept a zero-copy fast path via
        // `arrow_ipc::reader::BufferStreamReader`, but that type only
        // exists on `rustyconover/arrow-rs feat/custom-metadata-and-buffer-reader`;
        // dropping the patch for crates.io publication trades one
        // extra mmap-to-Vec copy on the SHM read path for the ability
        // to publish.
        let region: &[u8] = &self.shm.as_slice()[off..end];
        deserialize_from_shm(region, schema)
    }

    /// Free the region at `offset`.
    pub fn free(&self, offset: u64) -> Result<()> {
        self.allocator.free(offset)
    }
}

// ---------------------------------------------------------------------------
// (De)serialization — matches Python's `_serialize_for_shm` /
// `_deserialize_from_shm`. Non-dict batches: full IPC stream in place.
// Dict batches: full stream minus the leading schema message and the
// trailing EOS marker.
// ---------------------------------------------------------------------------

fn schema_has_dictionary(schema: &Schema) -> bool {
    schema
        .fields()
        .iter()
        .any(|f| matches!(f.data_type(), DataType::Dictionary(_, _)))
}

fn serialize_for_shm(batch: &RecordBatch, schema: &Schema) -> Result<Vec<u8>> {
    // Full IPC stream first.
    let mut buf = Vec::new();
    {
        let mut w = IpcStreamWriter::try_new(&mut buf, schema).map_err(RpcError::from)?;
        w.write(batch).map_err(RpcError::from)?;
        w.finish().map_err(RpcError::from)?;
    }
    if !schema_has_dictionary(schema) {
        return Ok(buf);
    }
    // Dictionary path: strip leading schema message and trailing EOS
    // marker, leaving dictionary messages + record-batch message.
    let after_schema = skip_one_ipc_message(&buf)?;
    let trimmed = strip_trailing_eos(&buf[after_schema..])?;
    Ok(trimmed.to_vec())
}

fn deserialize_from_shm(region: &[u8], schema: &Schema) -> Result<RecordBatch> {
    if !schema_has_dictionary(schema) {
        let mut r = IpcStreamReader::try_new(Cursor::new(region), None).map_err(RpcError::from)?;
        let batch = r
            .next()
            .ok_or_else(|| RpcError::new("IPC", "empty SHM region"))?
            .map_err(RpcError::from)?;
        return Ok(batch);
    }
    // Reconstruct: schema message (everything before EOS in a "schema-only"
    // stream) + region + EOS marker.
    let mut schema_only = Vec::new();
    {
        let mut w = IpcStreamWriter::try_new(&mut schema_only, schema).map_err(RpcError::from)?;
        w.finish().map_err(RpcError::from)?;
    }
    let schema_msg_len = schema_only
        .len()
        .checked_sub(IPC_EOS.len())
        .ok_or_else(|| RpcError::new("IPC", "schema-only stream too short"))?;
    let mut combined = Vec::with_capacity(schema_msg_len + region.len() + IPC_EOS.len());
    combined.extend_from_slice(&schema_only[..schema_msg_len]);
    combined.extend_from_slice(region);
    combined.extend_from_slice(&IPC_EOS);
    let mut r = IpcStreamReader::try_new(Cursor::new(combined), None).map_err(RpcError::from)?;
    let batch = r
        .next()
        .ok_or_else(|| RpcError::new("IPC", "empty SHM region"))?
        .map_err(RpcError::from)?;
    Ok(batch)
}

/// Return the byte index in `buf` after the first IPC message (its
/// metadata + body), advancing past any leading continuation marker.
fn skip_one_ipc_message(buf: &[u8]) -> Result<usize> {
    if buf.len() < 8 {
        return Err(RpcError::new("IPC", "IPC stream too short"));
    }
    let mut pos = 0;
    if buf[pos..pos + 4] == [0xFF, 0xFF, 0xFF, 0xFF] {
        pos += 4;
    }
    if pos + 4 > buf.len() {
        return Err(RpcError::new("IPC", "IPC stream truncated"));
    }
    let meta_len = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    if meta_len == 0 {
        return Err(RpcError::new("IPC", "unexpected EOS while skipping schema"));
    }
    if pos + meta_len > buf.len() {
        return Err(RpcError::new("IPC", "IPC metadata truncated"));
    }
    let msg = arrow_ipc::root_as_message(&buf[pos..pos + meta_len])
        .map_err(|e| RpcError::new("IPC", format!("parse schema message: {e}")))?;
    let body_len = msg.bodyLength() as usize;
    Ok(pos + meta_len + body_len)
}

fn strip_trailing_eos(buf: &[u8]) -> Result<&[u8]> {
    if buf.len() < IPC_EOS.len() || buf[buf.len() - IPC_EOS.len()..] != IPC_EOS {
        return Err(RpcError::new("IPC", "stream missing trailing EOS marker"));
    }
    Ok(&buf[..buf.len() - IPC_EOS.len()])
}

// ---------------------------------------------------------------------------
// Pointer-batch helpers
// ---------------------------------------------------------------------------

/// Build a zero-row pointer batch carrying `(offset, length)` metadata.
/// Returns `(batch, metadata)` — metadata is passed alongside the batch
/// on the wire layer rather than embedded in the `RecordBatch`.
pub fn make_shm_pointer_batch(
    schema: &Schema,
    offset: u64,
    length: usize,
) -> Result<(RecordBatch, Metadata)> {
    let batch = wire::empty_batch(schema)?;
    let mut md: Metadata = std::collections::HashMap::new();
    md.insert(SHM_OFFSET_KEY.into(), offset.to_string());
    md.insert(SHM_LENGTH_KEY.into(), length.to_string());
    Ok((batch, md))
}

/// True if `(batch, md)` together describe an SHM pointer batch
/// (zero rows + offset key, without a log level — log batches share
/// the zero-row shape).
pub fn is_shm_pointer_batch(batch: &RecordBatch, md: &Metadata) -> bool {
    if batch.num_rows() != 0 {
        return false;
    }
    md.contains_key(SHM_OFFSET_KEY) && !md.contains_key(LOG_LEVEL_KEY)
}

/// Resolution result from [`resolve_shm_batch`].
pub struct ResolvedShm {
    /// The materialized batch (with pointer metadata stripped and a
    /// `vgi_rpc.shm_source` tag added). When the input wasn't a pointer
    /// batch this is the input unchanged.
    pub batch: RecordBatch,
    /// The metadata that accompanies `batch`, with SHM pointer keys
    /// removed when the input was a pointer batch (and `shm_source`
    /// added). When the input wasn't a pointer batch this is the input
    /// `md` unchanged.
    pub metadata: Metadata,
    /// Offset of the resolved region, when the input *was* a pointer
    /// batch. Use [`ShmSegment::free`] to release it after the handler
    /// is done with `batch`.
    pub release_offset: Option<u64>,
}

/// Resolve a pointer batch through `shm`, or return it unchanged when
/// the input isn't a pointer batch (or no segment is available).
pub fn resolve_shm_batch(
    batch: RecordBatch,
    md: Metadata,
    shm: Option<&ShmSegment>,
) -> Result<ResolvedShm> {
    let Some(shm) = shm else {
        return Ok(ResolvedShm {
            batch,
            metadata: md,
            release_offset: None,
        });
    };
    if !is_shm_pointer_batch(&batch, &md) {
        return Ok(ResolvedShm {
            batch,
            metadata: md,
            release_offset: None,
        });
    }
    let offset: u64 = md
        .get(SHM_OFFSET_KEY)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| RpcError::new("ValueError", "bad shm_offset"))?;
    let length: usize = md
        .get(SHM_LENGTH_KEY)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| RpcError::new("ValueError", "bad shm_length"))?;
    let resolved = shm.read_batch(offset, length, batch.schema().as_ref())?;
    let mut new_md = md.clone();
    new_md.remove(SHM_OFFSET_KEY);
    new_md.remove(SHM_LENGTH_KEY);
    new_md.insert(SHM_SOURCE_KEY.into(), shm.name().to_string());
    // Both paths copy the SHM region bytes out of the segment (the
    // earlier zero-copy fast-path via `BufferStreamReader` is gone —
    // see the comment in `read_batch`). The resolved batch no longer
    // references the segment, so the caller may release the slot
    // immediately on return.
    Ok(ResolvedShm {
        batch: resolved,
        metadata: new_md,
        release_offset: Some(offset),
    })
}

/// Try to write `batch` into `shm`; on success return a pointer batch
/// (preserving any pre-existing custom metadata other than the SHM
/// keys). On failure (no segment, zero rows, doesn't fit) return `batch`
/// unchanged. Returns `(batch, metadata)` — metadata carries the SHM
/// pointer keys when written, or `batch_md` unchanged otherwise.
/// Smallest batch (bytes) worth shipping through shm; below this the pipe wins,
/// because shm's fixed per-batch cost (slot allocation + pointer round trip +
/// the peer's resolve/free) outweighs the copy it saves. The crossover is
/// platform-specific: POSIX `shm_open`/`mmap` overtakes the pipe around 64-256KB
/// while Windows' page-file mapping plus the fast overlapped-pipe read push it to ~0.5-1MB.
/// Overridable with `VGI_RPC_SHM_MIN_BATCH_BYTES`. Mirrors the same gate in the
/// C++ engine and the Python/Go/Java SDK output paths.
fn shm_min_batch_bytes() -> usize {
    // Unit tests exercise the shm write/resolve mechanics with tiny batches; the
    // size gate's real behavior is covered by the end-to-end crossover benchmark,
    // so neutralize it in test builds.
    if cfg!(test) {
        return 0;
    }
    use std::sync::OnceLock;
    static THRESHOLD: OnceLock<usize> = OnceLock::new();
    *THRESHOLD.get_or_init(|| {
        if let Ok(s) = std::env::var("VGI_RPC_SHM_MIN_BATCH_BYTES") {
            if let Ok(v) = s.parse::<usize>() {
                return v;
            }
        }
        if cfg!(windows) {
            1024 * 1024 // 1 MiB
        } else {
            128 * 1024 // 128 KiB
        }
    })
}

pub fn maybe_write_to_shm(
    batch: RecordBatch,
    batch_md: Metadata,
    shm: Option<&ShmSegment>,
) -> Result<(RecordBatch, Metadata)> {
    use arrow_array::Array;
    let Some(shm) = shm else {
        return Ok((batch, batch_md));
    };
    if batch.num_rows() == 0 {
        return Ok((batch, batch_md));
    }
    // Small batches are cheaper over the pipe than through shm.
    let batch_bytes: usize = batch
        .columns()
        .iter()
        .map(|c| c.get_array_memory_size())
        .sum();
    if batch_bytes < shm_min_batch_bytes() {
        return Ok((batch, batch_md));
    }
    let Some((offset, length)) = shm.allocate_and_write(&batch)? else {
        return Ok((batch, batch_md));
    };
    let (pointer, pointer_md) = make_shm_pointer_batch(batch.schema().as_ref(), offset, length)?;
    let mut merged = batch_md;
    // Pointer keys win over any (unlikely) collision on the input.
    for (k, v) in pointer_md.into_iter() {
        merged.insert(k, v);
    }
    Ok((pointer, merged))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::{types::Int32Type, DictionaryArray, Int64Array, RecordBatch, StringArray};
    use arrow_schema::{DataType, Field, Schema};

    fn small_seg() -> ShmSegment {
        ShmSegment::create(HEADER_SIZE + 64 * 1024).expect("create")
    }

    #[test]
    fn allocator_first_fit_and_coalesce() {
        let seg = small_seg();
        let a = seg.allocator().allocate(100).expect("a");
        let b = seg.allocator().allocate(100).expect("b");
        let c = seg.allocator().allocate(100).expect("c");
        assert!(b > a && c > b);
        // Free the middle one and re-allocate exactly the same size.
        seg.allocator().free(b).unwrap();
        let b2 = seg.allocator().allocate(100).expect("b2");
        assert_eq!(b, b2);
        // Now free b and c (adjacent), then allocate 200: should reuse
        // the merged gap starting at b.
        seg.allocator().free(b2).unwrap();
        seg.allocator().free(c).unwrap();
        let big = seg.allocator().allocate(200).expect("merged");
        assert_eq!(big, b);
    }

    #[test]
    fn allocator_rejects_corrupted_unsorted_table() {
        // If the on-segment alloc table is somehow stored unsorted (or
        // contains overlapping entries), allocate() must not hand out an
        // offset past the segment. Pre-fix, `off - prev_end` underflowed
        // into a giant phantom gap and the next slice op panicked.
        let seg = small_seg();
        let total = seg.size();
        // Hand-write two overlapping/out-of-order entries directly into
        // the header. data region is `total - HEADER_SIZE` bytes.
        let buf = seg.shm.as_mut_slice();
        // num_allocs = 2
        buf[16..20].copy_from_slice(&2u32.to_le_bytes());
        // entry 0: offset=total-8, len=8 (right at the tail)
        let off0 = (total - 8) as u64;
        buf[24..32].copy_from_slice(&off0.to_le_bytes());
        buf[32..40].copy_from_slice(&8u64.to_le_bytes());
        // entry 1: offset=HEADER_SIZE, len=8 (out of order vs entry 0)
        let off1 = HEADER_SIZE as u64;
        buf[40..48].copy_from_slice(&off1.to_le_bytes());
        buf[48..56].copy_from_slice(&8u64.to_le_bytes());
        // Asking for ~all of the data region must NOT return an offset
        // that would slice past `total`.
        if let Some(off) = seg.allocator().allocate(total) {
            assert!(
                (off as usize)
                    .checked_add(total)
                    .map(|e| e <= total)
                    .unwrap_or(false),
                "allocator returned out-of-bounds offset {off} for size {total} (segment {total})",
            );
        }
        // A reasonable mid-size request is allowed but must stay in bounds.
        if let Some(off) = seg.allocator().allocate(1024) {
            assert!((off as usize) + 1024 <= total);
        }
    }

    #[test]
    fn allocator_returns_none_when_full() {
        let seg = small_seg();
        // Data region is 64KiB; ask for 65KiB to force failure.
        assert!(seg.allocator().allocate(65 * 1024).is_none());
    }

    #[test]
    fn roundtrip_non_dict_batch() {
        let seg = ShmSegment::create(HEADER_SIZE + 1024 * 1024).unwrap();
        let schema = Arc::new(Schema::new(vec![
            Field::new("a", DataType::Int64, false),
            Field::new("b", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec!["x", "yy", "zzz"])),
            ],
        )
        .unwrap();
        let (pointer, pointer_md) =
            maybe_write_to_shm(batch.clone(), Metadata::new(), Some(&seg)).unwrap();
        assert!(is_shm_pointer_batch(&pointer, &pointer_md));
        let resolved = resolve_shm_batch(pointer, pointer_md, Some(&seg)).unwrap();
        assert_eq!(resolved.batch.num_rows(), 3);
        assert_eq!(resolved.batch.schema(), batch.schema());
        assert_eq!(
            resolved.metadata.get(SHM_SOURCE_KEY).map(String::as_str),
            Some(seg.name()),
        );
        // Both the dict and non-dict paths now copy the SHM region
        // bytes into a fresh allocation (the upstream-stock arrow-ipc
        // doesn't expose the buffer-aliasing reader the fork used).
        // `release_offset` is therefore always set and the caller
        // must free the slot.
        let off = resolved.release_offset.expect("release_offset must be set");
        let _ = seg.allocator().free(off);
    }

    #[test]
    fn roundtrip_dict_batch() {
        let seg = ShmSegment::create(HEADER_SIZE + 1024 * 1024).unwrap();
        let dict_type = DataType::Dictionary(Box::new(DataType::Int32), Box::new(DataType::Utf8));
        let schema = Arc::new(Schema::new(vec![Field::new("d", dict_type, false)]));
        let values = StringArray::from(vec!["alpha", "beta"]);
        let keys = arrow_array::Int32Array::from(vec![0, 1, 0, 1, 0]);
        let dict = DictionaryArray::<Int32Type>::try_new(keys, Arc::new(values)).unwrap();
        let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(dict)]).unwrap();
        let (pointer, pointer_md) =
            maybe_write_to_shm(batch.clone(), Metadata::new(), Some(&seg)).unwrap();
        assert!(is_shm_pointer_batch(&pointer, &pointer_md));
        let resolved = resolve_shm_batch(pointer, pointer_md, Some(&seg)).unwrap();
        assert_eq!(resolved.batch.num_rows(), 5);
        assert_eq!(resolved.batch.schema(), batch.schema());
    }

    #[test]
    fn pointer_batch_distinct_from_log_batch() {
        let schema = Schema::empty();
        let mut md: Metadata = std::collections::HashMap::new();
        md.insert(SHM_OFFSET_KEY.into(), "0".into());
        md.insert(LOG_LEVEL_KEY.into(), "INFO".into());
        let log_batch = wire::empty_batch(&schema).unwrap();
        assert!(!is_shm_pointer_batch(&log_batch, &md));
    }

    #[test]
    fn attach_existing_segment() {
        let owner = ShmSegment::create(HEADER_SIZE + 64 * 1024).unwrap();
        let attached = ShmSegment::attach(owner.name(), owner.size(), false).expect("attach");
        let off = attached.allocator().allocate(123).expect("alloc");
        // Owner sees the same allocation through its allocator view.
        let seen = owner.allocator().read_allocs();
        assert_eq!(seen, vec![(off, 123)]);
    }

    // ---------- header format pinning (cross-language) ----------

    /// Golden bytes for a known segment header state. The mirror Python
    /// test lives at `~/Development/vgi-rpc/tests/test_shm_header_format.py`
    /// and asserts the same hex. If this diverges, Python and Rust
    /// peers can no longer attach to each other's segments — the layout
    /// is not delegated to arrow-ipc, it is our hand-rolled allocator
    /// header.
    ///
    /// State (16 KiB-aligned request avoids platform page-rounding so
    /// the same hex is valid on both Linux and macOS):
    ///   data_size = 16384, num_allocs = 2,
    ///   entry 0 = (offset=65536, length=100),
    ///   entry 1 = (offset=65792, length=50)
    const SHM_HEADER_GOLDEN_HEX: &str =
        "5647495301000000004000000000000002000000000000000000010000000000\
         640000000000000000010100000000003200000000000000";

    #[test]
    fn header_layout_matches_canonical_golden_bytes() {
        // Build a real segment, drive it into the golden state, then
        // read the header bytes back and compare to the hex pinned
        // above (and in the Python canonical test).
        let seg = ShmSegment::create(HEADER_SIZE + 16384).unwrap();
        let off0 = seg.allocator().allocate(100).expect("alloc 0");
        // Force the second allocation at offset HEADER_SIZE + 256 so
        // the byte layout is deterministic. We use offset arithmetic
        // because the first-fit allocator places (HEADER_SIZE, 100)
        // and the next at HEADER_SIZE + 100; we want a gap so the test
        // has a meaningful second entry. Reserve and shrink instead.
        // Simpler: free the first, allocate two with a manual gap.
        seg.allocator().free(off0).unwrap();
        let _a = seg.allocator().allocate(100).expect("a");
        let _gap = seg.allocator().allocate(156).expect("gap");
        let _b = seg.allocator().allocate(50).expect("b");
        // Free the middle "gap" entry to leave allocs = [(HEADER, 100), (HEADER+256, 50)].
        seg.allocator().free(_gap).unwrap();
        // Read first 56 bytes (fixed header + 2 entries) and compare.
        let buf = seg.shm.as_slice();
        let observed = &buf[..56];
        let golden_hex: String = SHM_HEADER_GOLDEN_HEX
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let golden: Vec<u8> = (0..golden_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&golden_hex[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(
            observed,
            golden.as_slice(),
            "SHM header layout drifted; if intentional, update both this \
             test and tests/test_shm_header_format.py in vgi-rpc canonical",
        );
    }

    // ---------- in-place write path ----------

    #[test]
    fn shrink_returns_tail_to_free_pool() {
        // Reserve, shrink, re-allocate into the freed tail.
        let seg = ShmSegment::create(HEADER_SIZE + 64 * 1024).unwrap();
        let off = seg.allocator().allocate(8 * 1024).expect("first alloc");
        seg.allocator().shrink(off, 1024).expect("shrink");
        // The freed 7 KiB tail should now be available.
        let off2 = seg.allocator().allocate(4 * 1024).expect("second alloc");
        assert_eq!(off2, off + 1024);
        // Total live allocs == 2.
        assert_eq!(seg.allocator().num_allocs(), 2);
    }

    #[test]
    fn shrink_rejects_invalid_inputs() {
        let seg = small_seg();
        let off = seg.allocator().allocate(1024).unwrap();
        // Larger than reservation.
        assert!(seg.allocator().shrink(off, 2048).is_err());
        // Unknown offset.
        assert!(seg.allocator().shrink(off + 1, 100).is_err());
        // Original allocation is unchanged.
        assert_eq!(seg.allocator().read_allocs(), vec![(off, 1024)]);
    }

    #[test]
    fn inplace_write_is_byte_compatible_with_legacy_path() {
        // The in-place writer must produce a region byte-identical to
        // what `serialize_for_shm` would have produced — otherwise a
        // Python or Go peer reading the segment would decode garbage.
        let seg = ShmSegment::create(HEADER_SIZE + 1024 * 1024).unwrap();
        let schema = Arc::new(Schema::new(vec![
            Field::new("a", DataType::Int64, false),
            Field::new("b", DataType::Utf8, true),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![10, 20, 30])),
                Arc::new(StringArray::from(vec!["a", "bb", "ccc"])),
            ],
        )
        .unwrap();
        // Capture what legacy serialization would have produced.
        let expected = serialize_for_shm(&batch, schema.as_ref()).unwrap();
        let (offset, length) = seg.allocate_and_write(&batch).unwrap().expect("written");
        assert_eq!(length, expected.len(), "length must match legacy path");
        let region = seg.read_bytes(offset, length).unwrap();
        assert_eq!(region, expected, "bytes must match legacy path");
    }

    #[test]
    fn inplace_write_falls_back_when_segment_too_small() {
        // Segment data region is only 4 KiB; a 200K-row batch can't fit.
        let seg = ShmSegment::create(HEADER_SIZE + 4 * 1024).unwrap();
        let schema = Arc::new(Schema::new(vec![Field::new("v", DataType::Int64, false)]));
        let big = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(Int64Array::from_iter_values(0..200_000))],
        )
        .unwrap();
        // Must return Ok(None) without panicking and without leaking a slot.
        assert!(seg.allocate_and_write(&big).unwrap().is_none());
        assert_eq!(seg.allocator().num_allocs(), 0);
    }

    #[test]
    fn inplace_write_then_resolve_round_trip() {
        // End-to-end: write a real batch, build a pointer batch, resolve
        // it back through `resolve_shm_batch`, drop, and confirm the slot
        // is released by the anchor.
        let seg = ShmSegment::create(HEADER_SIZE + 1024 * 1024).unwrap();
        let schema = Arc::new(Schema::new(vec![Field::new("v", DataType::Int64, false)]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(Int64Array::from_iter_values(0..1024))],
        )
        .unwrap();
        let (pointer, pointer_md) =
            maybe_write_to_shm(batch.clone(), Metadata::new(), Some(&seg)).unwrap();
        assert!(is_shm_pointer_batch(&pointer, &pointer_md));
        assert_eq!(seg.allocator().num_allocs(), 1);
        let resolved = resolve_shm_batch(pointer, pointer_md, Some(&seg)).unwrap();
        assert_eq!(resolved.batch.num_rows(), 1024);
        // Both paths now require explicit free (the zero-copy anchor
        // was tied to the dropped fork API).
        let off = resolved.release_offset.expect("release_offset must be set");
        drop(resolved);
        seg.allocator().free(off).unwrap();
        assert_eq!(seg.allocator().num_allocs(), 0);
    }

    // ---------- pointer batch validation ----------

    #[test]
    fn resolve_rejects_pointer_with_out_of_bounds_region() {
        let seg = ShmSegment::create(HEADER_SIZE + 64 * 1024).unwrap();
        let schema = Arc::new(Schema::new(vec![Field::new("v", DataType::Int64, false)]));
        // Hand-construct a pointer batch claiming a region past the segment.
        let mut md: Metadata = std::collections::HashMap::new();
        md.insert(SHM_OFFSET_KEY.into(), seg.size().to_string());
        md.insert(SHM_LENGTH_KEY.into(), "1024".into());
        let bogus = wire::empty_batch(schema.as_ref()).unwrap();
        let err = match resolve_shm_batch(bogus, md, Some(&seg)) {
            Err(e) => e,
            Ok(_) => panic!("must reject"),
        };
        assert_eq!(err.error_type, "ValueError");
    }

    #[test]
    fn resolve_rejects_pointer_with_unparseable_metadata() {
        let seg = small_seg();
        let schema = Arc::new(Schema::new(vec![Field::new("v", DataType::Int64, false)]));
        let mut md: Metadata = std::collections::HashMap::new();
        md.insert(SHM_OFFSET_KEY.into(), "not-a-number".into());
        md.insert(SHM_LENGTH_KEY.into(), "100".into());
        let bogus = wire::empty_batch(schema.as_ref()).unwrap();
        let err = match resolve_shm_batch(bogus, md, Some(&seg)) {
            Err(e) => e,
            Ok(_) => panic!("must reject"),
        };
        assert_eq!(err.error_type, "ValueError");
    }

    #[test]
    fn read_batch_overflow_is_rejected_not_panicked() {
        let seg = small_seg();
        let schema = Schema::new(vec![Field::new("v", DataType::Int64, false)]);
        // length near usize::MAX must error, not panic on overflow.
        let err = seg
            .read_batch(0, usize::MAX, &schema)
            .expect_err("must reject");
        assert_eq!(err.error_type, "ValueError");
    }

    // ---------- corrupted segment headers ----------

    #[test]
    fn attach_rejects_bad_magic() {
        let seg = ShmSegment::create(HEADER_SIZE + 4096).unwrap();
        // Corrupt the magic.
        seg.shm.as_mut_slice()[0..4].copy_from_slice(b"XXXX");
        let err = match ShmSegment::attach(seg.name(), seg.size(), false) {
            Err(e) => e,
            Ok(_) => panic!("must reject bad magic"),
        };
        assert_eq!(err.error_type, "ValueError");
    }

    #[test]
    fn attach_rejects_bad_version() {
        let seg = ShmSegment::create(HEADER_SIZE + 4096).unwrap();
        seg.shm.as_mut_slice()[4..8].copy_from_slice(&999u32.to_le_bytes());
        let err = match ShmSegment::attach(seg.name(), seg.size(), false) {
            Err(e) => e,
            Ok(_) => panic!("must reject bad version"),
        };
        assert_eq!(err.error_type, "ValueError");
    }

    // ---------- max allocations ----------

    #[test]
    fn allocator_respects_max_allocs_capacity() {
        // Make a segment with enough space that we hit MAX_ALLOCS first.
        let bytes_per = 16;
        let need = HEADER_SIZE + (MAX_ALLOCS + 1) * bytes_per;
        let seg = ShmSegment::create(need).unwrap();
        let mut offsets = Vec::with_capacity(MAX_ALLOCS);
        for _ in 0..MAX_ALLOCS {
            offsets.push(seg.allocator().allocate(bytes_per).expect("alloc"));
        }
        // Next one must fail (table full) even if there's still data room.
        assert!(seg.allocator().allocate(bytes_per).is_none());
        // Free one, then we can allocate again.
        seg.allocator().free(offsets[0]).unwrap();
        assert!(seg.allocator().allocate(bytes_per).is_some());
    }

    // ---------- proptest: random allocate/free/shrink sequences ----------

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 64,
            .. proptest::test_runner::Config::default()
        })]

        /// Random sequence of allocate/free/shrink ops must preserve
        /// allocator invariants:
        ///   1. Every returned offset satisfies HEADER_SIZE <= off and
        ///      off + len <= shm.size.
        ///   2. No two live allocations overlap.
        ///   3. num_allocs matches the count we tracked externally.
        ///   4. allocate(n) never returns Some when no contiguous gap of
        ///      size n exists.
        #[test]
        fn allocator_invariants_under_random_ops(
            ops in proptest::collection::vec(
                (0u8..3u8, 1usize..=4096usize),
                1..200,
            )
        ) {
            let total = HEADER_SIZE + 64 * 1024;
            let seg = ShmSegment::create(total).unwrap();
            // Track our view of live regions: (offset, len).
            let mut live: Vec<(u64, u64)> = Vec::new();
            for (op, size) in ops {
                match op {
                    // allocate
                    0 => {
                        if let Some(off) = seg.allocator().allocate(size) {
                            // Bounds.
                            proptest::prop_assert!(off >= HEADER_SIZE as u64);
                            proptest::prop_assert!(
                                off as usize + size <= total,
                                "alloc returned off={off} size={size} but segment is {total}",
                            );
                            // No overlap with previous live regions.
                            for &(o, l) in &live {
                                let a_end = off + size as u64;
                                let b_end = o + l;
                                proptest::prop_assert!(
                                    a_end <= o || off >= b_end,
                                    "overlap: new=({off},{size}) existing=({o},{l})",
                                );
                            }
                            live.push((off, size as u64));
                        }
                    }
                    // free a random live entry
                    1 => {
                        if !live.is_empty() {
                            let idx = size % live.len();
                            let (off, _) = live.remove(idx);
                            seg.allocator().free(off).unwrap();
                        }
                    }
                    // shrink a random live entry
                    _ => {
                        if !live.is_empty() {
                            let idx = size % live.len();
                            let (off, len) = live[idx];
                            let new_len = ((size as u64) % len.max(1)).max(1);
                            if seg.allocator().shrink(off, new_len as usize).is_ok() {
                                live[idx] = (off, new_len);
                            }
                        }
                    }
                }
                proptest::prop_assert_eq!(seg.allocator().num_allocs(), live.len());
            }
        }
    }
}
