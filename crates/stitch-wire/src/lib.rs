//! High-performance microsecond transport bus and wire protocol facade for the Stitch ecosystem.

#![cfg_attr(not(feature = "std"), no_std)]

pub use stitch_wire_core;
pub use stitch_wire_core::{
    FrameReader, FrameView, OptimizationProfile, ResyncStats, StreamResyncParser, VectoredFrame,
    WIRE_MAGIC, WIRE_VERSION_1, WireError, WireFlags, WireHeader, checked_frame_total_len, crc,
    error, find_magic, find_magic_swar, frame, pack_frame, pack_frame_vectored, resync,
    resync_frame, simd, unpack_frame, varint,
};

#[cfg(feature = "data")]
pub mod data_adapter {
    use crate::{
        OptimizationProfile as WireProfile, WireError, WireFlags, WireHeader, pack_frame,
        unpack_frame,
    };
    use stitch_data::prelude::{OptimizationProfile as DataProfile, StitchRecord};

    #[inline]
    fn to_data_profile(p: WireProfile) -> DataProfile {
        match p {
            WireProfile::Direct => DataProfile::Direct,
            WireProfile::Realtime => DataProfile::Realtime,
            WireProfile::Balanced => DataProfile::Balanced,
            WireProfile::MaxDensity => DataProfile::MaxDensity,
        }
    }

    #[inline]
    #[allow(dead_code)]
    fn to_wire_profile(p: DataProfile) -> WireProfile {
        match p {
            DataProfile::Direct => WireProfile::Direct,
            DataProfile::Realtime => WireProfile::Realtime,
            DataProfile::Balanced => WireProfile::Balanced,
            DataProfile::MaxDensity => WireProfile::MaxDensity,
        }
    }

    /// Packs a `StitchRecord` directly into a wire frame with schema fingerprint validation.
    pub fn pack_record<T: StitchRecord>(
        record: &T,
        profile: WireProfile,
        scratch: &mut [u8],
        dst: &mut [u8],
    ) -> Result<usize, WireError> {
        let payload_len = record
            .encode_record_profile(to_data_profile(profile), scratch)
            .map_err(|_| WireError::PayloadDecodeError)?;

        let header = WireHeader {
            profile,
            flags: WireFlags {
                is_compressed: profile != WireProfile::Direct,
                is_chunked: false,
                has_schema_hash: true,
            },
            payload_len,
            schema_hash: Some(T::SCHEMA_HASH),
        };
        pack_frame(&header, &scratch[..payload_len], dst)
    }

    /// Unpacks a `StitchRecord` from a wire frame, validating CRC32 and schema hash.
    pub fn unpack_record<T: StitchRecord>(src: &[u8]) -> Result<T, WireError> {
        let (header, payload) = unpack_frame(src)?;
        if header.flags.has_schema_hash
            && let Some(actual) = header.schema_hash
            && actual != T::SCHEMA_HASH
        {
            return Err(WireError::SchemaMismatch {
                expected: T::SCHEMA_HASH,
                actual,
            });
        }
        let (record, consumed) = T::decode_record_profile(payload, to_data_profile(header.profile))
            .map_err(|_| WireError::PayloadDecodeError)?;
        if consumed != payload.len() {
            return Err(WireError::PayloadDecodeError);
        }
        Ok(record)
    }
}

/// Unified prelude re-exporting key transport primitives.
pub mod prelude {
    pub use stitch_wire_core::crc::{
        crc32_castagnoli, crc32_castagnoli_finalize, crc32_castagnoli_init,
        crc32_castagnoli_slices, crc32_castagnoli_update,
    };
    pub use stitch_wire_core::error::WireError;
    pub use stitch_wire_core::frame::{
        FrameReader, FrameView, OptimizationProfile, VectoredFrame, WIRE_MAGIC, WIRE_VERSION_1,
        WireFlags, WireHeader, checked_frame_total_len, pack_frame, pack_frame_vectored,
        unpack_frame,
    };
    pub use stitch_wire_core::resync::{
        ResyncStats, StreamResyncParser, find_magic, find_magic_swar, resync_frame,
    };
    pub use stitch_wire_core::varint::{decode_prefix_varint, encode_prefix_varint};

    #[cfg(feature = "data")]
    pub use crate::data_adapter::{pack_record, unpack_record};
}
