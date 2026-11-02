//! WebAssembly (WASM) browser runtime adapter for the Stitch Wire protocol.
//!
//! Provides zero-allocation, `#![no_std]` WebAssembly exports for:
//! - Frame header inspection
//! - Fast checksum verification
//! - SWAR frame boundary scanning in continuous incoming web streams (WebSockets / WebTransport)

#![no_std]

use core::slice;
use stitch_wire_core::crc::crc32_castagnoli;
use stitch_wire_core::frame::unpack_frame;
use stitch_wire_core::resync::find_magic_swar;

/// Unpacks a frame and returns its payload length and schema hash.
///
/// Returns `0` on format/CRC error, or `1` on valid frame.
///
/// # Safety
/// `frame_ptr` must point to `frame_len` bytes in linear memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_unpack_frame_view(
    frame_ptr: *const u8,
    frame_len: usize,
    out_payload_offset: *mut usize,
    out_payload_len: *mut usize,
    out_schema_hash: *mut u64,
) -> i32 {
    if frame_ptr.is_null()
        || frame_len == 0
        || out_payload_offset.is_null()
        || out_payload_len.is_null()
    {
        return 0;
    }

    // SAFETY: Ensured by caller.
    let buf = unsafe { slice::from_raw_parts(frame_ptr, frame_len) };

    match unpack_frame(buf) {
        Ok((header, payload)) => {
            let offset = payload.as_ptr() as usize - frame_ptr as usize;
            // SAFETY: Checked non-null above.
            unsafe {
                *out_payload_offset = offset;
                *out_payload_len = payload.len();
                if !out_schema_hash.is_null() {
                    *out_schema_hash = header.schema_hash.unwrap_or(0);
                }
            }
            1
        }
        Err(_) => 0,
    }
}

/// Computes Castagnoli CRC32 across a buffer in WASM linear memory.
///
/// # Safety
/// `data_ptr` must point to at least `len` bytes in WASM linear memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_crc32(data_ptr: *const u8, len: usize) -> u32 {
    if data_ptr.is_null() || len == 0 {
        return 0;
    }
    // SAFETY: Ensured by caller.
    let bytes = unsafe { slice::from_raw_parts(data_ptr, len) };
    crc32_castagnoli(bytes)
}

/// Scans linear memory for the 2-byte Stitch wire magic (`0x5354` / "ST") using SWAR.
///
/// Returns offset in bytes, or `usize::MAX` if not found.
///
/// # Safety
/// `data_ptr` must point to at least `len` bytes in WASM linear memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wasm_find_magic(data_ptr: *const u8, len: usize) -> usize {
    if data_ptr.is_null() || len == 0 {
        return usize::MAX;
    }
    // SAFETY: Ensured by caller.
    let bytes = unsafe { slice::from_raw_parts(data_ptr, len) };
    find_magic_swar(bytes).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stitch_wire_core::frame::{OptimizationProfile, WireFlags, WireHeader, pack_frame};

    #[test]
    fn test_wasm_adapter_roundtrip() {
        let payload = b"WASM browser frame test payload!";
        let mut frame_buf = [0u8; 128];

        let header = WireHeader {
            profile: OptimizationProfile::Balanced,
            flags: WireFlags {
                is_compressed: false,
                is_chunked: false,
                has_schema_hash: true,
            },
            payload_len: payload.len(),
            schema_hash: Some(0x1234_5678_9ABC_DEF0),
        };

        let written = pack_frame(&header, payload, &mut frame_buf).unwrap();

        let mut offset = 0usize;
        let mut len = 0usize;
        let mut hash = 0u64;

        // SAFETY: Test pointers to stack variables.
        let status = unsafe {
            wasm_unpack_frame_view(
                frame_buf.as_ptr(),
                written,
                &mut offset,
                &mut len,
                &mut hash,
            )
        };

        assert_eq!(status, 1);
        assert_eq!(len, payload.len());
        assert_eq!(hash, 0x1234_5678_9ABC_DEF0);
        assert_eq!(&frame_buf[offset..offset + len], payload);
    }
}
