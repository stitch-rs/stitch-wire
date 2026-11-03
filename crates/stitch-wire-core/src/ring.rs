//! Lock-free Single-Producer Single-Consumer (SPSC) Ring Buffer.
//!
//! Designed for microsecond-latency shared-memory IPC, DMA circular buffers,
//! and inter-thread frame dispatching with zero dynamic heap allocations.
//!
//! # Mechanical Sympathy & Cache Invariants
//! - `head` (written by producer) and `tail` (written by consumer) are aligned
//!   to distinct 64-byte L1D cache lines (`#[repr(align(64))]`), preventing
//!   cache-line bouncing and false sharing on multi-core architectures.
//! - Uses strict power-of-two capacity for fast bitwise indexing: `idx & (capacity - 1)`.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Padded 64-byte atomic position preventing false sharing.
#[repr(align(64))]
pub struct CachePaddedAtomicUsize {
    value: AtomicUsize,
}

impl CachePaddedAtomicUsize {
    /// Creates a new cache-line padded atomic usize.
    pub const fn new(val: usize) -> Self {
        Self {
            value: AtomicUsize::new(val),
        }
    }

    /// Loads the value with the given memory ordering.
    #[inline(always)]
    pub fn load(&self, order: Ordering) -> usize {
        self.value.load(order)
    }

    /// Stores the value with the given memory ordering.
    #[inline(always)]
    pub fn store(&self, val: usize, order: Ordering) {
        self.value.store(val, order);
    }
}

/// Zero-allocation, lock-free SPSC byte ring buffer.
///
/// Can operate directly over pre-allocated static buffers, shared memory (`mmap`),
/// or stack scratchpads.
pub struct SpscByteRing<'a> {
    buffer: &'a mut [u8],
    capacity: usize,
    mask: usize,
    head: CachePaddedAtomicUsize,
    tail: CachePaddedAtomicUsize,
}

impl<'a> SpscByteRing<'a> {
    /// Creates a new SPSC ring buffer wrapping the provided `buffer`.
    ///
    /// # Panics / Invariants
    /// - `buffer.len()` must be a power of two.
    pub fn new(buffer: &'a mut [u8]) -> Self {
        let capacity = buffer.len();
        assert!(
            capacity.is_power_of_two(),
            "SpscByteRing buffer length must be a power of two"
        );
        let mask = capacity - 1;

        Self {
            buffer,
            capacity,
            mask,
            head: CachePaddedAtomicUsize::new(0),
            tail: CachePaddedAtomicUsize::new(0),
        }
    }

    /// Returns the total capacity of the ring buffer.
    #[inline(always)]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of readable bytes currently available in the ring.
    #[inline]
    pub fn available_read(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }

    /// Returns the writable capacity remaining before buffer overflow.
    #[inline]
    pub fn available_write(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        self.capacity - head.wrapping_sub(tail)
    }

    /// Leases a contiguous slice of bytes for reading without intermediate copying.
    ///
    /// Returns `&[u8]` slice up to the ring wrap-around boundary.
    #[inline]
    pub fn grant_read(&self) -> &[u8] {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Relaxed);
        let count = head.wrapping_sub(tail);
        if count == 0 {
            return &[];
        }

        let tail_idx = tail & self.mask;
        let contiguous = (self.capacity - tail_idx).min(count);
        // SAFETY: The consumer is the single reader for [tail..tail + contiguous],
        // and the producer has already committed these bytes prior to head increment with Release ordering.
        unsafe {
            let ptr = self.buffer.as_ptr().add(tail_idx);
            core::slice::from_raw_parts(ptr, contiguous)
        }
    }

    /// Commits `count` consumed bytes, advancing the consumer `tail` pointer.
    #[inline]
    pub fn commit_read(&self, count: usize) {
        if count == 0 {
            return;
        }
        let tail = self.tail.load(Ordering::Relaxed);
        self.tail.store(tail.wrapping_add(count), Ordering::Release);
    }

    /// Leases a contiguous slice of mutable bytes for writing without intermediate copying.
    ///
    /// Returns `&mut [u8]` slice up to the ring wrap-around boundary.
    #[inline]
    pub fn grant_write(&mut self) -> &mut [u8] {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        let free = self.capacity - head.wrapping_sub(tail);
        if free == 0 {
            return &mut [];
        }

        let head_idx = head & self.mask;
        let contiguous = (self.capacity - head_idx).min(free);
        // SAFETY: The producer is the single writer for [head..head + contiguous],
        // and the consumer has already read and committed past this region with Release ordering.
        unsafe {
            let ptr = self.buffer.as_mut_ptr().add(head_idx);
            core::slice::from_raw_parts_mut(ptr, contiguous)
        }
    }

    /// Commits `count` written bytes, advancing the producer `head` pointer.
    #[inline]
    pub fn commit_write(&mut self, count: usize) {
        assert!(
            count <= self.available_write(),
            "commit_write count exceeds available"
        );
        if count == 0 {
            return;
        }
        let head = self.head.load(Ordering::Relaxed);
        self.head.store(head.wrapping_add(count), Ordering::Release);
    }

    /// Writes `src` bytes into the ring buffer across contiguous slices.
    ///
    /// Returns the number of bytes written.
    pub fn write_slice(&mut self, mut src: &[u8]) -> usize {
        let mut total_written = 0;
        while !src.is_empty() {
            let grant = self.grant_write();
            if grant.is_empty() {
                break;
            }
            let to_copy = grant.len().min(src.len());
            grant[..to_copy].copy_from_slice(&src[..to_copy]);
            self.commit_write(to_copy);
            total_written += to_copy;
            src = &src[to_copy..];
        }
        total_written
    }

    /// Reads up to `dst.len()` bytes from the ring buffer into `dst`.
    ///
    /// Returns the number of bytes read.
    pub fn read_slice(&self, mut dst: &mut [u8]) -> usize {
        let mut total_read = 0;
        while !dst.is_empty() {
            let grant = self.grant_read();
            if grant.is_empty() {
                break;
            }
            let to_copy = grant.len().min(dst.len());
            dst[..to_copy].copy_from_slice(&grant[..to_copy]);
            self.commit_read(to_copy);
            total_read += to_copy;
            dst = &mut dst[to_copy..];
        }
        total_read
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spsc_ring_basic_write_read() {
        let mut storage = [0u8; 128];
        let mut ring = SpscByteRing::new(&mut storage);

        assert_eq!(ring.capacity(), 128);
        assert_eq!(ring.available_read(), 0);
        assert_eq!(ring.available_write(), 128);

        let data = b"Hello High-Performance Wire Transport";
        let written = ring.write_slice(data);
        assert_eq!(written, data.len());
        assert_eq!(ring.available_read(), data.len());

        let mut read_buf = [0u8; 64];
        let read = ring.read_slice(&mut read_buf[..written]);
        assert_eq!(read, data.len());
        assert_eq!(&read_buf[..read], data);
        assert_eq!(ring.available_read(), 0);
    }

    #[test]
    fn test_spsc_ring_wraparound() {
        let mut storage = [0u8; 16];
        let mut ring = SpscByteRing::new(&mut storage);

        // Fill 12 bytes
        let written = ring.write_slice(b"123456789012");
        assert_eq!(written, 12);

        // Consume 8 bytes
        let mut buf = [0u8; 8];
        let read = ring.read_slice(&mut buf);
        assert_eq!(read, 8);
        assert_eq!(&buf, b"12345678");

        // Now head is at 12, tail is at 8. 12 bytes available for writing (capacity 16 - 4)
        let written2 = ring.write_slice(b"ABCDEFGH");
        assert_eq!(written2, 8);

        // Total available read: 4 + 8 = 12
        assert_eq!(ring.available_read(), 12);

        let mut read_all = [0u8; 12];
        let read_count = ring.read_slice(&mut read_all);
        assert_eq!(read_count, 12);
        assert_eq!(&read_all, b"9012ABCDEFGH");
    }

    #[test]
    fn test_spsc_ring_grant_lease() {
        let mut storage = [0u8; 32];
        let mut ring = SpscByteRing::new(&mut storage);

        {
            let grant = ring.grant_write();
            assert_eq!(grant.len(), 32);
            grant[..4].copy_from_slice(b"ABCD");
            ring.commit_write(4);
        }

        {
            let read_grant = ring.grant_read();
            assert_eq!(read_grant.len(), 4);
            assert_eq!(read_grant, b"ABCD");
            ring.commit_read(4);
        }

        assert_eq!(ring.available_read(), 0);
    }
}
