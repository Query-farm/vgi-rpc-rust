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
//! [`SHM_SEGMENT_NAME_KEY`]: crate::metadata::SHM_SEGMENT_NAME_KEY
//! [`SHM_SEGMENT_SIZE_KEY`]: crate::metadata::SHM_SEGMENT_SIZE_KEY

use std::ffi::CString;
use std::io::Cursor;
use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_buffer::Buffer;
use arrow_ipc::reader::{BufferStreamReader, StreamReader as IpcStreamReader};
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

/// Owned handle to a POSIX shared-memory segment.
///
/// On non-POSIX platforms compilation fails; cross-platform support is
/// deferred (Windows would need named file mappings + a different name
/// resolution scheme).
struct PosixShm {
    name: String,
    ptr: *mut u8,
    size: usize,
    /// True if this handle owns the OS object (created with `create=true`)
    /// and is responsible for `shm_unlink` on drop. Server-side dynamic
    /// attachments set this to `false`.
    track: bool,
}

unsafe impl Send for PosixShm {}
unsafe impl Sync for PosixShm {}

// `PosixShm` carries a raw pointer (the mmap region) but the data it
// points at is not invalidated by panics — the OS owns the page table
// entries until `munmap`, and our drop runs only when no Arc clones
// (including any held by an `arrow_buffer::Buffer`) remain. Marking it
// `RefUnwindSafe` lets us hand an `Arc<PosixShm>` to
// `Buffer::from_custom_allocation` as the owner of an aliased view.
impl std::panic::RefUnwindSafe for PosixShm {}

/// `Allocation` owner that **also** releases the allocator slot when
/// the last buffer alias drops. Used as the owner of a zero-copy
/// [`Buffer`] aliasing an SHM region: the slot is freed automatically
/// when no `RecordBatch` (and no column buffer of one) is still
/// holding a reference. This is what makes the freed slot safe to
/// reuse without corrupting in-flight batches.
struct ShmBatchAnchor {
    shm: Arc<PosixShm>,
    offset: u64,
}

impl std::panic::RefUnwindSafe for ShmBatchAnchor {}

impl Drop for ShmBatchAnchor {
    fn drop(&mut self) {
        // Same allocator instance state lives in the segment header;
        // re-attach is essentially free (a couple of integer reads).
        if let Ok(allocator) = ShmAllocator::attach(self.shm.clone()) {
            let _ = allocator.free(self.offset);
        }
    }
}

impl std::fmt::Debug for ShmBatchAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShmBatchAnchor")
            .field("offset", &self.offset)
            .finish()
    }
}

#[cfg(unix)]
fn make_shm_name() -> String {
    // Python's `multiprocessing.shared_memory` uses `psm_<8 hex>_<8 hex>`
    // on macOS and `/<rand>` on Linux. Either works as long as the
    // server is given the literal string; we match Python's leading-slash
    // convention.
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = unsafe { libc::getpid() };
    format!("/vgi_rpc_{:x}_{:x}", pid, nanos as u64)
}

#[cfg(unix)]
impl PosixShm {
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
impl Drop for PosixShm {
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
// ShmAllocator — first-fit allocator stored in segment header
// ---------------------------------------------------------------------------

/// First-fit allocator over the segment's data region. State lives in
/// the segment header; adjacent free regions coalesce implicitly.
pub struct ShmAllocator {
    shm: Arc<PosixShm>,
    total_size: usize,
}

impl ShmAllocator {
    /// Initialize the header at the start of `shm` with zero allocations.
    fn initialize(shm: &PosixShm) -> Result<()> {
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

    fn attach(shm: Arc<PosixShm>) -> Result<Self> {
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

    fn read_allocs(&self) -> Vec<(u64, u64)> {
        let buf = self.shm.as_slice();
        let n = u32::from_le_bytes(buf[16..20].try_into().unwrap()) as usize;
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
        let size = size as u64;
        let data_end = self.total_size as u64;
        let mut prev_end = HEADER_SIZE as u64;
        for (i, (off, len)) in allocs.iter().enumerate() {
            let gap = off - prev_end;
            if gap >= size {
                allocs.insert(i, (prev_end, size));
                self.write_allocs(&allocs);
                return Some(prev_end);
            }
            prev_end = off + len;
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
    shm: Arc<PosixShm>,
    allocator: ShmAllocator,
}

impl ShmSegment {
    /// Create a new segment of `size` bytes. The handle owns the OS
    /// object; dropping `ShmSegment` calls `shm_unlink`.
    pub fn create(size: usize) -> Result<Self> {
        let shm = Arc::new(PosixShm::create(size)?);
        ShmAllocator::initialize(&shm)?;
        let allocator = ShmAllocator::attach(shm.clone())?;
        Ok(Self { shm, allocator })
    }

    /// Attach to an existing segment by name. `track = false` means the
    /// caller is *not* the owner — the OS object will not be unlinked
    /// on drop. Servers handling a client-advertised segment use this.
    pub fn attach(name: &str, size: usize, track: bool) -> Result<Self> {
        let shm = Arc::new(PosixShm::attach(name, size, track)?);
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
        let off = offset as usize;
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
        let bytes = serialize_for_shm(batch, schema.as_ref())?;
        let size = bytes.len();
        let Some(offset) = self.allocator.allocate(size) else {
            return Ok(None);
        };
        let dst = &mut self.shm.as_mut_slice()[offset as usize..offset as usize + size];
        dst.copy_from_slice(&bytes);
        Ok(Some((offset, size)))
    }

    /// Inverse of [`Self::allocate_and_write`]: read a record batch
    /// previously written into the segment.
    ///
    /// For non-dictionary schemas this is **fully zero-copy**: the
    /// returned [`RecordBatch`]'s column buffers alias the SHM mapping
    /// directly via [`Buffer::from_custom_allocation`], with an
    /// [`Arc`] of the underlying [`PosixShm`] keeping the mmap alive
    /// as long as any column buffer references it.
    ///
    /// For dictionary-encoded schemas the SHM region holds only the
    /// dictionary + record-batch messages (no schema, no EOS), so we
    /// stitch a synthetic stream around them; that path still copies
    /// the region into a `Vec` for the moment.
    pub fn read_batch(&self, offset: u64, length: usize, schema: &Schema) -> Result<RecordBatch> {
        let off = offset as usize;
        let end = off + length;
        if end > self.shm.size {
            return Err(RpcError::new(
                "ValueError",
                format!("shm region out of bounds: {off}..{end} > {}", self.shm.size),
            ));
        }
        if !schema_has_dictionary(schema) {
            // Zero-copy: alias the mmap region as an Arrow `Buffer`,
            // anchored on a `ShmBatchAnchor` so the allocator slot is
            // released exactly when the last column buffer referencing
            // it drops. This is what lets us return ownership of the
            // slot to the segment without invalidating live batch data.
            let ptr = unsafe { self.shm.ptr.add(off) };
            let nn = std::ptr::NonNull::new(ptr)
                .ok_or_else(|| RpcError::new("ValueError", "null shm pointer"))?;
            let anchor = Arc::new(ShmBatchAnchor {
                shm: self.shm.clone(),
                offset,
            });
            let buf = unsafe { Buffer::from_custom_allocation(nn, length, anchor) };
            let mut r = BufferStreamReader::try_new(buf).map_err(RpcError::from)?;
            let batch = r
                .next()
                .ok_or_else(|| RpcError::new("IPC", "empty SHM region"))?
                .map_err(RpcError::from)?;
            return Ok(batch);
        }
        // Dictionary path: stitch a synthetic stream and decode normally.
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
pub fn make_shm_pointer_batch(schema: &Schema, offset: u64, length: usize) -> Result<RecordBatch> {
    let batch = wire::empty_batch(schema)?;
    let mut md: Metadata = std::collections::HashMap::new();
    md.insert(SHM_OFFSET_KEY.into(), offset.to_string());
    md.insert(SHM_LENGTH_KEY.into(), length.to_string());
    Ok(batch.with_custom_metadata(md))
}

/// True if `batch` is an SHM pointer batch (zero rows + offset key,
/// without a log level — log batches share the zero-row shape).
pub fn is_shm_pointer_batch(batch: &RecordBatch) -> bool {
    if batch.num_rows() != 0 {
        return false;
    }
    let md = batch.custom_metadata();
    md.contains_key(SHM_OFFSET_KEY) && !md.contains_key(LOG_LEVEL_KEY)
}

/// Resolution result from [`resolve_shm_batch`].
pub struct ResolvedShm {
    /// The materialized batch (with pointer metadata stripped and a
    /// `vgi_rpc.shm_source` tag added). When the input wasn't a pointer
    /// batch this is the input unchanged.
    pub batch: RecordBatch,
    /// Offset of the resolved region, when the input *was* a pointer
    /// batch. Use [`ShmSegment::free`] to release it after the handler
    /// is done with `batch`.
    pub release_offset: Option<u64>,
}

/// Resolve a pointer batch through `shm`, or return it unchanged when
/// the input isn't a pointer batch (or no segment is available).
pub fn resolve_shm_batch(batch: RecordBatch, shm: Option<&ShmSegment>) -> Result<ResolvedShm> {
    let Some(shm) = shm else {
        return Ok(ResolvedShm {
            batch,
            release_offset: None,
        });
    };
    if !is_shm_pointer_batch(&batch) {
        return Ok(ResolvedShm {
            batch,
            release_offset: None,
        });
    }
    let md = batch.custom_metadata();
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
    // The non-dict (zero-copy) path embeds an `Allocation` owner that
    // frees the slot on last-buffer-drop, so the caller must NOT free
    // explicitly — that would race the in-flight batch's column data.
    // The dict path copies the bytes into a fresh allocation, so the
    // slot is safe to release as soon as `read_batch` returns.
    let release_offset = if schema_has_dictionary(batch.schema().as_ref()) {
        Some(offset)
    } else {
        None
    };
    Ok(ResolvedShm {
        batch: resolved.with_custom_metadata(new_md),
        release_offset,
    })
}

/// Try to write `batch` into `shm`; on success return a pointer batch
/// (preserving any pre-existing custom metadata other than the SHM
/// keys). On failure (no segment, zero rows, doesn't fit) return `batch`
/// unchanged.
pub fn maybe_write_to_shm(batch: RecordBatch, shm: Option<&ShmSegment>) -> Result<RecordBatch> {
    let Some(shm) = shm else {
        return Ok(batch);
    };
    if batch.num_rows() == 0 {
        return Ok(batch);
    }
    let Some((offset, length)) = shm.allocate_and_write(&batch)? else {
        return Ok(batch);
    };
    let mut pointer = make_shm_pointer_batch(batch.schema().as_ref(), offset, length)?;
    let mut merged = batch.custom_metadata().clone();
    // Pointer keys win over any (unlikely) collision on the input.
    for (k, v) in pointer.custom_metadata().iter() {
        merged.insert(k.clone(), v.clone());
    }
    pointer = pointer.with_custom_metadata(merged);
    Ok(pointer)
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
        let pointer = maybe_write_to_shm(batch.clone(), Some(&seg)).unwrap();
        assert!(is_shm_pointer_batch(&pointer));
        let resolved = resolve_shm_batch(pointer, Some(&seg)).unwrap();
        assert_eq!(resolved.batch.num_rows(), 3);
        assert_eq!(resolved.batch.schema(), batch.schema());
        assert_eq!(
            resolved
                .batch
                .custom_metadata()
                .get(SHM_SOURCE_KEY)
                .map(String::as_str),
            Some(seg.name()),
        );
        // Non-dict path is now zero-copy: the resolved batch's column
        // buffers alias the SHM region. Freeing is deferred to the
        // anchor's drop, so `release_offset` is None and the caller
        // must not free explicitly. Release happens when `resolved.batch`
        // (and any clones of its columns) drop at end-of-scope.
        assert!(resolved.release_offset.is_none());
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
        let pointer = maybe_write_to_shm(batch.clone(), Some(&seg)).unwrap();
        assert!(is_shm_pointer_batch(&pointer));
        let resolved = resolve_shm_batch(pointer, Some(&seg)).unwrap();
        assert_eq!(resolved.batch.num_rows(), 5);
        assert_eq!(resolved.batch.schema(), batch.schema());
    }

    #[test]
    fn pointer_batch_distinct_from_log_batch() {
        let schema = Schema::empty();
        let mut md: Metadata = std::collections::HashMap::new();
        md.insert(SHM_OFFSET_KEY.into(), "0".into());
        md.insert(LOG_LEVEL_KEY.into(), "INFO".into());
        let log_batch = wire::empty_batch(&schema).unwrap().with_custom_metadata(md);
        assert!(!is_shm_pointer_batch(&log_batch));
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
}
