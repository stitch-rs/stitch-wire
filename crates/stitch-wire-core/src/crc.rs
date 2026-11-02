//! Hardware-accelerated and table-based CRC32 implementation (Castagnoli polynomial).
//!
//! Provides hardware-accelerated CRC32-C (Castagnoli, polynomial 0x1EDC6F41 / 0x82F63B78)
//! with architecture-specific fast paths (x86_64 SSE4.2 and ARM64 PMULL/CRC), backed by
//! a compile-time generated slicing-by-8 software fallback for `#![no_std]` and generic targets.

#[cfg(all(target_arch = "x86_64", not(miri)))]
use core::sync::atomic::{AtomicU8, Ordering};

/// Computes the slicing-by-8 table at compile time.
const fn make_slicing_table() -> [[u32; 256]; 8] {
    let mut table = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
            j += 1;
        }
        table[0][i] = crc;
        i += 1;
    }

    let mut slice = 1;
    while slice < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = table[slice - 1][i];
            table[slice][i] = (prev >> 8) ^ table[0][(prev & 0xFF) as usize];
            i += 1;
        }
        slice += 1;
    }
    table
}

/// Slicing-by-8 lookup table (8 KiB, embedded in `.rodata`).
const SLICING_TABLE: [[u32; 256]; 8] = make_slicing_table();

/// Updates a running CRC using the slicing-by-8 algorithm.
#[inline]
pub fn crc32_slicing_by_8_update(mut crc: u32, mut data: &[u8]) -> u32 {
    while data.len() >= 8 {
        let term = crc ^ u32::from_le_bytes(data[0..4].try_into().unwrap());
        crc = SLICING_TABLE[7][(term & 0xFF) as usize]
            ^ SLICING_TABLE[6][((term >> 8) & 0xFF) as usize]
            ^ SLICING_TABLE[5][((term >> 16) & 0xFF) as usize]
            ^ SLICING_TABLE[4][(term >> 24) as usize]
            ^ SLICING_TABLE[3][data[4] as usize]
            ^ SLICING_TABLE[2][data[5] as usize]
            ^ SLICING_TABLE[1][data[6] as usize]
            ^ SLICING_TABLE[0][data[7] as usize];
        data = &data[8..];
    }

    for &b in data {
        crc = (crc >> 8) ^ SLICING_TABLE[0][((crc as u8) ^ b) as usize];
    }

    crc
}

/// Software reference and fallback using slicing-by-8 algorithm.
#[inline]
pub fn crc32_slicing_by_8(data: &[u8]) -> u32 {
    !crc32_slicing_by_8_update(0xFFFF_FFFF, data)
}

/// Bitwise scalar reference implementation (preserved for verification and parity checks).
#[inline]
pub fn crc32_bitwise_reference(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    !crc
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn crc32_x86_sse42_update(crc: u32, mut data: &[u8]) -> u32 {
    let mut crc64 = crc as u64;

    // Unroll x4: 32 bytes per iteration
    while data.len() >= 32 {
        let c0 = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let c1 = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let c2 = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let c3 = u64::from_le_bytes(data[24..32].try_into().unwrap());

        crc64 = core::arch::x86_64::_mm_crc32_u64(crc64, c0);
        crc64 = core::arch::x86_64::_mm_crc32_u64(crc64, c1);
        crc64 = core::arch::x86_64::_mm_crc32_u64(crc64, c2);
        crc64 = core::arch::x86_64::_mm_crc32_u64(crc64, c3);

        data = &data[32..];
    }

    // Process remaining 8-byte chunks
    while data.len() >= 8 {
        let chunk = u64::from_le_bytes(data[0..8].try_into().unwrap());
        crc64 = core::arch::x86_64::_mm_crc32_u64(crc64, chunk);
        data = &data[8..];
    }

    // Process remaining tail bytes (1..7 bytes)
    let mut crc32 = crc64 as u32;
    for &b in data {
        crc32 = core::arch::x86_64::_mm_crc32_u8(crc32, b);
    }

    crc32
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn has_sse42() -> bool {
    #[cfg(miri)]
    return false;

    #[cfg(not(miri))]
    {
        // 0 = uninitialized, 1 = supported, 2 = unsupported
        static STATE: AtomicU8 = AtomicU8::new(0);

        let val = STATE.load(Ordering::Relaxed);
        if val == 1 {
            return true;
        }
        if val == 2 {
            return false;
        }

        // Perform CPUID detection (bit 20 of ECX for function 1 indicates SSE4.2)
        let cpuid = core::arch::x86_64::__cpuid(1);
        let supported = (cpuid.ecx & (1 << 20)) != 0;

        STATE.store(if supported { 1 } else { 2 }, Ordering::Relaxed);
        supported
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc")]
unsafe fn crc32_aarch64_crc_update(mut crc: u32, mut data: &[u8]) -> u32 {
    while data.len() >= 8 {
        let chunk = u64::from_le_bytes(data[0..8].try_into().unwrap());
        crc = core::arch::aarch64::__crc32cd(crc, chunk);
        data = &data[8..];
    }

    for &b in data {
        crc = core::arch::aarch64::__crc32cb(crc, b);
    }

    crc
}

/// Returns the initial state for Castagnoli CRC32 calculation (`0xFFFF_FFFF`).
#[inline]
pub const fn crc32_castagnoli_init() -> u32 {
    0xFFFF_FFFF
}

/// Finalizes a running Castagnoli CRC32 state by inverting its bits.
#[inline]
pub const fn crc32_castagnoli_finalize(running_crc: u32) -> u32 {
    !running_crc
}

/// Updates a running Castagnoli CRC32 state with additional data bytes.
#[inline]
pub fn crc32_castagnoli_update(running_crc: u32, data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        #[cfg(target_feature = "sse4.2")]
        {
            // SAFETY: target_feature sse4.2 is verified at compile time.
            return unsafe { crc32_x86_sse42_update(running_crc, data) };
        }
        #[cfg(not(target_feature = "sse4.2"))]
        {
            if has_sse42() {
                // SAFETY: SSE4.2 CPU support verified dynamically via CPUID.
                return unsafe { crc32_x86_sse42_update(running_crc, data) };
            }
        }
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "crc"))]
    {
        // SAFETY: ARMv8 CRC feature verified at compile time.
        return unsafe { crc32_aarch64_crc_update(running_crc, data) };
    }

    #[allow(unreachable_code)]
    crc32_slicing_by_8_update(running_crc, data)
}

/// Computes CRC32 (Castagnoli 0x82F63B78) across multiple non-contiguous slices as if they were concatenated.
#[inline]
pub fn crc32_castagnoli_slices(slices: &[&[u8]]) -> u32 {
    let mut running = crc32_castagnoli_init();
    for slice in slices {
        running = crc32_castagnoli_update(running, slice);
    }
    crc32_castagnoli_finalize(running)
}

/// Computes CRC32 (Castagnoli 0x82F63B78) over a byte slice.
///
/// Automatically uses hardware acceleration (SSE4.2 on x86_64, ARMv8 CRC on AArch64)
/// when available, falling back to compile-time slicing-by-8 in `#![no_std]` or legacy targets.
#[inline]
pub fn crc32_castagnoli(data: &[u8]) -> u32 {
    crc32_castagnoli_finalize(crc32_castagnoli_update(crc32_castagnoli_init(), data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_deterministic() {
        let data = b"123456789";
        let crc = crc32_castagnoli(data);
        assert_eq!(crc, 0xE3069283);
    }

    #[test]
    fn test_crc32_slicing_matches_reference() {
        let data = b"123456789";
        assert_eq!(crc32_slicing_by_8(data), 0xE3069283);
        assert_eq!(crc32_bitwise_reference(data), 0xE3069283);
    }

    #[test]
    fn test_crc32_hardware_and_software_parity_all_lengths() {
        // Test parity between hardware and software across all alignment and length boundaries
        let mut buffer = [0u8; 513];
        for (i, b) in buffer.iter_mut().enumerate() {
            *b = (i * 31 + 7) as u8;
        }

        for len in 0..=513 {
            let slice = &buffer[..len];
            let bitwise = crc32_bitwise_reference(slice);
            let slicing = crc32_slicing_by_8(slice);
            let unified = crc32_castagnoli(slice);

            assert_eq!(slicing, bitwise, "Slicing-by-8 mismatch at length {}", len);
            assert_eq!(
                unified, bitwise,
                "crc32_castagnoli mismatch at length {}",
                len
            );
        }
    }

    #[test]
    fn test_crc32_slices_parity_all_boundaries() {
        let mut buffer = [0u8; 256];
        for (i, b) in buffer.iter_mut().enumerate() {
            *b = (i * 37 + 13) as u8;
        }

        let full_crc = crc32_castagnoli(&buffer);

        // Split into 2 slices at every possible cut point
        for split in 0..=buffer.len() {
            let s1 = &buffer[..split];
            let s2 = &buffer[split..];
            let slices_crc = crc32_castagnoli_slices(&[s1, s2]);
            assert_eq!(
                slices_crc, full_crc,
                "2-slice parity failed at split {}",
                split
            );
        }

        // Split into 3 slices (e.g. Header [20B], Payload [200B], Tail [36B])
        let s1 = &buffer[..20];
        let s2 = &buffer[20..220];
        let s3 = &buffer[220..];
        let slices3_crc = crc32_castagnoli_slices(&[s1, s2, s3]);
        assert_eq!(slices3_crc, full_crc, "3-slice parity failed");
    }
}
