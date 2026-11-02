//! C-ABI Foreign Function Interface (FFI) for Stitch Wire.
//!
//! Exposes zero-allocation, thread-safe, panic-free C functions for embedding
//! Stitch Wire framing into C, C++, Go, and Python runtimes.

use std::panic::catch_unwind;
use std::slice;
use stitch_wire_core::crc::crc32_castagnoli;
use stitch_wire_core::frame::{
    OptimizationProfile, WireFlags, WireHeader, pack_frame, unpack_frame,
};
use stitch_wire_core::resync::find_magic_swar;

/// C representation of wire frame options.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct StitchWireOptions {
    pub profile: u8,
    pub flags: u8,
    pub schema_hash: u64,
}

/// Calculates Castagnoli CRC32 with hardware acceleration.
///
/// # Safety
/// `data` must point to at least `len` valid initialized bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stitch_crc32(data: *const u8, len: usize) -> u32 {
    let res = catch_unwind(|| {
        if data.is_null() || len == 0 {
            return 0;
        }
        // SAFETY: Ensured by caller.
        let bytes = unsafe { slice::from_raw_parts(data, len) };
        crc32_castagnoli(bytes)
    });
    res.unwrap_or(0)
}

/// Packs a frame into `out_buf`.
///
/// Returns bytes written on success, or 0 on error.
///
/// # Safety
/// Pointers must point to valid memory buffers with corresponding sizes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stitch_pack_frame(
    opts: *const StitchWireOptions,
    payload: *const u8,
    payload_len: usize,
    out_buf: *mut u8,
    out_capacity: usize,
) -> usize {
    let res = catch_unwind(|| {
        if out_buf.is_null() || out_capacity == 0 {
            return 0;
        }
        let payload_slice = if payload.is_null() || payload_len == 0 {
            &[]
        } else {
            // SAFETY: Caller guarantees valid slice.
            unsafe { slice::from_raw_parts(payload, payload_len) }
        };

        // SAFETY: Caller guarantees valid out buffer.
        let dst = unsafe { slice::from_raw_parts_mut(out_buf, out_capacity) };

        let (profile, flags, schema_hash) = if opts.is_null() {
            (
                OptimizationProfile::Balanced,
                WireFlags {
                    is_compressed: false,
                    is_chunked: false,
                    has_schema_hash: false,
                },
                None,
            )
        } else {
            // SAFETY: Non-null pointer from caller.
            let opt = unsafe { &*opts };
            let p = match opt.profile {
                0 => OptimizationProfile::Direct,
                1 => OptimizationProfile::Realtime,
                3 => OptimizationProfile::MaxDensity,
                _ => OptimizationProfile::Balanced,
            };
            let f = WireFlags {
                is_compressed: (opt.flags & 0x01) != 0,
                is_chunked: (opt.flags & 0x02) != 0,
                has_schema_hash: opt.schema_hash != 0,
            };
            let sh = if opt.schema_hash != 0 {
                Some(opt.schema_hash)
            } else {
                None
            };
            (p, f, sh)
        };

        let header = WireHeader {
            profile,
            flags,
            payload_len,
            schema_hash,
        };

        pack_frame(&header, payload_slice, dst).unwrap_or_default()
    });

    res.unwrap_or(0)
}

/// Unpacks and verifies a frame from `frame_buf`.
///
/// Returns 1 on success, 0 on checksum/format error.
///
/// # Safety
/// Pointers must point to valid memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stitch_unpack_frame(
    frame_buf: *const u8,
    frame_len: usize,
    out_payload_ptr: *mut *const u8,
    out_payload_len: *mut usize,
    out_schema_hash: *mut u64,
) -> i32 {
    let res = catch_unwind(|| {
        if frame_buf.is_null()
            || frame_len == 0
            || out_payload_ptr.is_null()
            || out_payload_len.is_null()
        {
            return 0;
        }

        // SAFETY: Caller guarantees valid frame buffer.
        let buf = unsafe { slice::from_raw_parts(frame_buf, frame_len) };

        match unpack_frame(buf) {
            Ok((header, payload)) => {
                // SAFETY: Pointers checked non-null above.
                unsafe {
                    *out_payload_ptr = payload.as_ptr();
                    *out_payload_len = payload.len();
                    if !out_schema_hash.is_null() {
                        *out_schema_hash = header.schema_hash.unwrap_or(0);
                    }
                }
                1
            }
            Err(_) => 0,
        }
    });

    res.unwrap_or(0)
}

/// SWAR-accelerated search for Stitch wire magic bytes (0x5354 / "ST").
///
/// # Safety
/// `data` must point to at least `len` valid initialized bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stitch_find_magic(data: *const u8, len: usize) -> usize {
    let res = catch_unwind(|| {
        if data.is_null() || len == 0 {
            return usize::MAX;
        }
        // SAFETY: Caller guarantees valid data.
        let bytes = unsafe { slice::from_raw_parts(data, len) };
        find_magic_swar(bytes).unwrap_or(usize::MAX)
    });

    res.unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_abi_pack_and_unpack_roundtrip() {
        let payload = b"Hello from C-ABI Stitch Wire!";
        let mut frame_buf = [0u8; 128];

        let opts = StitchWireOptions {
            profile: 2, // Balanced
            flags: 1,   // Compressed
            schema_hash: 0xDEAD_BEEF_CAFE_BABE,
        };

        // SAFETY: Valid local arrays.
        let written = unsafe {
            stitch_pack_frame(
                &opts,
                payload.as_ptr(),
                payload.len(),
                frame_buf.as_mut_ptr(),
                frame_buf.len(),
            )
        };

        assert!(written > payload.len());

        let mut out_ptr: *const u8 = std::ptr::null();
        let mut out_len: usize = 0;
        let mut out_hash: u64 = 0;

        // SAFETY: Valid local arrays and pointers.
        let ok = unsafe {
            stitch_unpack_frame(
                frame_buf.as_ptr(),
                written,
                &mut out_ptr,
                &mut out_len,
                &mut out_hash,
            )
        };

        assert_eq!(ok, 1);
        assert_eq!(out_len, payload.len());
        assert_eq!(out_hash, 0xDEAD_BEEF_CAFE_BABE);

        // SAFETY: Valid payload slice.
        let unpacked_slice = unsafe { slice::from_raw_parts(out_ptr, out_len) };
        assert_eq!(unpacked_slice, payload);
    }
}
