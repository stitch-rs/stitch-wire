//! High-throughput parallel chunk streaming and direct memory transfer engine.

use std::sync::atomic::{AtomicU32, Ordering};
use stitch_wire_core::{WireError, crc::crc32_castagnoli, transfer::TransferChunkDesc};

/// High-performance transfer sink writing chunks directly into target memory buffers.
pub struct MemoryTransferSink<'a> {
    buffer: &'a mut [u8],
    received_chunks: AtomicU32,
    total_chunks: u32,
}

impl<'a> MemoryTransferSink<'a> {
    /// Constructs a sink over a mutable memory buffer (e.g. `memmap2::MmapMut`).
    pub fn new(buffer: &'a mut [u8], total_chunks: u32) -> Self {
        Self {
            buffer,
            received_chunks: AtomicU32::new(0),
            total_chunks,
        }
    }

    /// Writes an incoming chunk directly to its precalculated file offset.
    ///
    /// Validates bounds and optional hardware Castagnoli CRC32.
    pub fn write_chunk(
        &mut self,
        desc: &TransferChunkDesc,
        chunk_data: &[u8],
        verify_crc: bool,
    ) -> Result<u32, WireError> {
        let start = desc.file_offset as usize;
        let end = start + desc.chunk_len as usize;

        if end > self.buffer.len() || chunk_data.len() != desc.chunk_len as usize {
            return Err(WireError::UnexpectedEof {
                required: end,
                available: self.buffer.len(),
            });
        }

        if verify_crc && desc.expected_crc32 != 0 {
            let actual_crc = crc32_castagnoli(chunk_data);
            if actual_crc != desc.expected_crc32 {
                return Err(WireError::ChecksumMismatch {
                    expected: desc.expected_crc32,
                    actual: actual_crc,
                });
            }
        }

        // Direct memory copy (can be swapped with silicon_kit streaming stores)
        self.buffer[start..end].copy_from_slice(chunk_data);

        let completed = self.received_chunks.fetch_add(1, Ordering::Release) + 1;
        Ok(completed)
    }

    /// Checks if all chunks in the session have arrived.
    #[inline]
    pub fn is_complete(&self) -> bool {
        self.received_chunks.load(Ordering::Acquire) >= self.total_chunks
    }

    /// Returns the count of chunks received so far.
    #[inline]
    pub fn completed_chunks(&self) -> u32 {
        self.received_chunks.load(Ordering::Acquire)
    }
}
