//! Parallel multi-channel chunk streaming and direct memory transfer engine.
//!
//! Provides zero-copy, branchless descriptors and state machines for splitting
//! massive continuous binary containers (`.flb`, `.flw`, `.fld`) into independent
//! chunk ranges streamed simultaneously across $N$ parallel network channels (QUIC/TCP/UDP)
//! and written directly into memory-mapped buffers.

/// Exact 32-byte chunk transfer descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TransferChunkDesc {
    /// Global file offset where this chunk begins (64-byte aligned).
    pub file_offset: u64,
    /// Byte length of the chunk payload.
    pub chunk_len: u32,
    /// Chunk sequence index within the transfer session.
    pub chunk_index: u32,
    /// Tier priority (0 = Critical/Collision BVH, 1 = Geometry, 2 = Textures, 3 = Sounds).
    pub tier: u8,
    /// Transfer channel assigned to stream this chunk.
    pub channel_id: u8,
    /// Flags (bit 0: compressed via Zstd, bit 1: terminal chunk of tier).
    pub flags: u8,
    /// Reserved zero padding.
    pub _pad: u8,
    /// Expected Castagnoli CRC32 hash of chunk data.
    pub expected_crc32: u32,
    /// Reserved alignment padding to 32 bytes.
    pub _reserved: [u8; 8],
}

const _: () = assert!(core::mem::size_of::<TransferChunkDesc>() == 32);

/// Chunk transfer session header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TransferSessionHeader {
    /// Magic identifier: `b"STTR"` (Stitch Transfer, `0x52545453` LE)
    pub magic: u32,
    /// Protocol version
    pub version: u16,
    /// Number of active parallel streaming channels
    pub channel_count: u16,
    /// Total resource payload length in bytes
    pub total_resource_size: u64,
    /// Total number of chunks in session
    pub total_chunks: u32,
    /// Nominal chunk size (e.g. 64 KB or 256 KB)
    pub chunk_size: u32,
    /// BLAKE3/CRC32 root integrity token
    pub integrity_token: u64,
}

const _: () = assert!(core::mem::size_of::<TransferSessionHeader>() == 32);

/// Zero-allocation chunk partitioner.
#[derive(Debug, Clone, Copy)]
pub struct ChunkPartitioner {
    total_size: u64,
    chunk_size: u32,
    total_chunks: u32,
    channels: u16,
}

impl ChunkPartitioner {
    /// Initializes a new partitioner for dividing a file of `total_size` bytes into `chunk_size` blocks.
    #[inline]
    pub const fn new(total_size: u64, chunk_size: u32, channels: u16) -> Self {
        let total_chunks = if total_size == 0 || chunk_size == 0 {
            0
        } else {
            total_size.div_ceil(chunk_size as u64) as u32
        };

        Self {
            total_size,
            chunk_size,
            total_chunks,
            channels: if channels == 0 { 1 } else { channels },
        }
    }

    /// Total number of chunks required to transmit the container.
    #[inline(always)]
    pub const fn total_chunks(&self) -> u32 {
        self.total_chunks
    }

    /// Computes the transfer descriptor for a given chunk index.
    #[inline]
    pub fn chunk_desc(&self, chunk_index: u32, tier: u8) -> Option<TransferChunkDesc> {
        if chunk_index >= self.total_chunks {
            return None;
        }

        let file_offset = chunk_index as u64 * self.chunk_size as u64;
        let remaining = self.total_size - file_offset;
        let chunk_len = if remaining < self.chunk_size as u64 {
            remaining as u32
        } else {
            self.chunk_size
        };

        let channel_id = (chunk_index % self.channels as u32) as u8;

        Some(TransferChunkDesc {
            file_offset,
            chunk_len,
            chunk_index,
            tier,
            channel_id,
            flags: 0,
            _pad: 0,
            expected_crc32: 0,
            _reserved: [0; 8],
        })
    }
}
