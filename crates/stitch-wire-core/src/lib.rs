//! Core `#![no_std]` framing, streaming resynchronization, and hardware Castagnoli CRC32.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod crc;
pub mod error;
pub mod frame;
pub mod resync;
pub mod ring;
pub mod simd;
pub mod varint;

pub use crc::{
    crc32_castagnoli, crc32_castagnoli_finalize, crc32_castagnoli_init, crc32_castagnoli_slices,
    crc32_castagnoli_update,
};
pub use error::WireError;
pub use frame::{
    FrameReader, FrameView, OptimizationProfile, VectoredFrame, WIRE_MAGIC, WIRE_VERSION_1,
    WireFlags, WireHeader, checked_frame_total_len, pack_frame, pack_frame_vectored, unpack_frame,
};
pub use resync::{ResyncStats, StreamResyncParser, find_magic, find_magic_swar, resync_frame};
pub use ring::{CachePaddedAtomicUsize, SpscByteRing};
pub use varint::{decode_prefix_varint, encode_prefix_varint};
