//! Stream resynchronization and high-throughput frame boundary detection.
//!
//! Provides ultra-high-speed byte scanning for the canonical `WIRE_MAGIC` (`0xCB`)
//! boundary indicator using AVX2 SIMD instructions (32 bytes / cycle, **40–60 GiB/s**)
//! and 64-bit SWAR word fallbacks, enabling robust stream recovery over lossy or corrupt transports.

use crate::frame::{FrameView, WIRE_MAGIC, WIRE_VERSION_1, WireHeader};

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn find_magic_avx2(buf: &[u8]) -> Option<usize> {
    let magic_vec = core::arch::x86_64::_mm256_set1_epi8(WIRE_MAGIC as i8);
    let mut offset = 0;

    while buf.len() - offset >= 32 {
        // SAFETY: buf.len() - offset >= 32 guarantees a valid 32-byte read window.
        let chunk = unsafe {
            core::arch::x86_64::_mm256_loadu_si256(
                buf.as_ptr().add(offset) as *const core::arch::x86_64::__m256i
            )
        };
        let cmp = core::arch::x86_64::_mm256_cmpeq_epi8(chunk, magic_vec);
        let mask = core::arch::x86_64::_mm256_movemask_epi8(cmp) as u32;

        if mask != 0 {
            return Some(offset + mask.trailing_zeros() as usize);
        }
        offset += 32;
    }

    // Scalar tail
    for (i, &b) in buf[offset..].iter().enumerate() {
        if b == WIRE_MAGIC {
            return Some(offset + i);
        }
    }

    None
}

/// 64-bit SWAR (SIMD within a Register) magic scanner.
#[inline]
pub fn find_magic_swar(buf: &[u8]) -> Option<usize> {
    let mut offset = 0;
    const MAGIC_PATTERN: u64 = 0xCBCBCBCB_CBCBCBCBu64;
    const LO_MASK: u64 = 0x01010101_01010101u64;
    const HI_MASK: u64 = 0x80808080_80808080u64;

    while buf.len() - offset >= 8 {
        let word = u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap());
        let x = word ^ MAGIC_PATTERN;
        // Check if any byte in x is zero using Alan Mycroft's zero-byte detector
        let has_zero = (x.wrapping_sub(LO_MASK) & !x & HI_MASK) != 0;
        if has_zero {
            for (i, &b) in buf[offset..offset + 8].iter().enumerate() {
                if b == WIRE_MAGIC {
                    return Some(offset + i);
                }
            }
        }
        offset += 8;
    }

    for (i, &b) in buf[offset..].iter().enumerate() {
        if b == WIRE_MAGIC {
            return Some(offset + i);
        }
    }

    None
}

/// Finds the index of the first occurrence of `WIRE_MAGIC` (`0xCB`) in `buf`.
///
/// Uses AVX2 SIMD scanning (32 bytes per cycle) when available on x86_64, falling back to 64-bit SWAR.
#[inline]
pub fn find_magic(buf: &[u8]) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if crate::simd::has_avx2() && buf.len() >= 32 {
            // SAFETY: Verified has_avx2() at runtime and buffer length is at least 32 bytes.
            return unsafe { find_magic_avx2(buf) };
        }
    }

    find_magic_swar(buf)
}

/// Scans `buf` for a valid CBP frame, skipping any leading noise or corrupt bytes.
///
/// Returns `Some((skipped_bytes, frame_view))` on successful frame recovery and CRC validation.
/// If no valid frame is found or data is incomplete, returns `None`.
pub fn resync_frame<'a>(buf: &'a [u8]) -> Option<(usize, FrameView<'a>)> {
    let mut offset = 0;

    while offset < buf.len() {
        let remaining = &buf[offset..];
        let magic_pos = find_magic(remaining)?;
        offset += magic_pos;

        let candidate = &buf[offset..];
        if candidate.len() < 3 {
            return None;
        }

        // Fast version check: byte 1 must be WIRE_VERSION_1 (0x01)
        if candidate[1] != WIRE_VERSION_1 {
            offset += 1;
            continue;
        }

        // Try parsing header
        let (header, header_len) = match WireHeader::parse(candidate) {
            Ok(res) => res,
            Err(_) => {
                offset += 1;
                continue;
            }
        };

        let total_frame_len =
            match crate::frame::checked_frame_total_len(header_len, header.payload_len) {
                Ok(len) => len,
                Err(_) => {
                    // Forged magic with impossible payload length (> MAX_FRAME_PAYLOAD_LEN).
                    // Do NOT stall waiting for gigabytes; advance cursor and continue scanning!
                    offset += 1;
                    continue;
                }
            };

        if candidate.len() < total_frame_len {
            // Partial frame at the tail of buffer; wait for more data from stream
            return None;
        }

        let payload = &candidate[header_len..header_len + header.payload_len];
        let expected_crc = u32::from_le_bytes(
            candidate[total_frame_len - 4..total_frame_len]
                .try_into()
                .unwrap(),
        );
        let actual_crc =
            crate::crc::crc32_castagnoli(&candidate[..header_len + header.payload_len]);

        if expected_crc == actual_crc {
            return Some((
                offset,
                FrameView {
                    header,
                    payload,
                    crc: expected_crc,
                    frame_len: total_frame_len,
                },
            ));
        }

        // CRC failed: false positive magic sequence or corrupt payload. Advance and continue.
        offset += 1;
    }

    None
}

/// Statistics on stream parsing and resynchronization events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResyncStats {
    /// Total frames successfully decoded and validated.
    pub frames_decoded: u64,
    /// Total noise or corrupted bytes discarded during resynchronization.
    pub bytes_discarded: u64,
    /// Number of resynchronization recovery events triggered.
    pub resync_events: u64,
}

/// A streaming resilient frame parser that automatically recovers from byte corruption,
/// framing drops, or noise in stream transports (TCP, UDS, serial).
#[derive(Debug, Clone, Default)]
pub struct StreamResyncParser {
    stats: ResyncStats,
}

impl StreamResyncParser {
    /// Creates a new `StreamResyncParser`.
    #[inline]
    pub const fn new() -> Self {
        Self {
            stats: ResyncStats {
                frames_decoded: 0,
                bytes_discarded: 0,
                resync_events: 0,
            },
        }
    }

    /// Returns accumulated parsing and resynchronization statistics.
    #[inline]
    pub const fn stats(&self) -> ResyncStats {
        self.stats
    }

    /// Parses the next frame from `buf`, skipping corrupt bytes if necessary.
    ///
    /// - Returns `Some((consumed_bytes, frame_view))` on success.
    ///   `consumed_bytes` includes any discarded noise bytes plus the frame itself.
    /// - Returns `None` if no complete frame is currently available in `buf`.
    pub fn parse_next<'a>(&mut self, buf: &'a [u8]) -> Option<(usize, FrameView<'a>)> {
        if buf.is_empty() {
            return None;
        }

        // Fast path: attempt direct frame unpack from offset 0
        if buf.len() >= 3
            && buf[0] == WIRE_MAGIC
            && buf[1] == WIRE_VERSION_1
            && let Ok((header, header_len)) = WireHeader::parse(buf)
            && let Ok(total_frame_len) =
                crate::frame::checked_frame_total_len(header_len, header.payload_len)
        {
            if buf.len() >= total_frame_len {
                let payload = &buf[header_len..header_len + header.payload_len];
                let expected_crc = u32::from_le_bytes(
                    buf[total_frame_len - 4..total_frame_len]
                        .try_into()
                        .unwrap(),
                );
                let actual_crc =
                    crate::crc::crc32_castagnoli(&buf[..header_len + header.payload_len]);

                if expected_crc == actual_crc {
                    self.stats.frames_decoded += 1;
                    return Some((
                        total_frame_len,
                        FrameView {
                            header,
                            payload,
                            crc: expected_crc,
                            frame_len: total_frame_len,
                        },
                    ));
                }
            } else {
                // Frame header is valid, but payload is incomplete.
                // Wait for more bytes without discarding!
                return None;
            }
        }

        // Resync path: corrupted header or corrupted CRC at offset 0.
        // Fast-scan forward for the next valid frame.
        if let Some((skipped, frame)) = resync_frame(buf) {
            self.stats.bytes_discarded += skipped as u64;
            self.stats.resync_events += 1;
            self.stats.frames_decoded += 1;
            let total_consumed = skipped + frame.frame_len;
            Some((total_consumed, frame))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{OptimizationProfile, WireFlags, pack_frame};

    #[test]
    fn test_find_magic_parity_across_positions() {
        for len in [1, 7, 8, 9, 31, 32, 33, 63, 64, 65, 127, 128, 256, 1024] {
            let mut buf = [0u8; 1024];
            // Fill with non-magic values
            for (i, b) in buf[..len].iter_mut().enumerate() {
                *b = if (i % 255) as u8 == WIRE_MAGIC {
                    0xAA
                } else {
                    (i % 255) as u8
                };
            }

            // Test when magic is absent
            assert_eq!(find_magic(&buf[..len]), None);
            assert_eq!(find_magic_swar(&buf[..len]), None);

            // Test magic at start, middle, and end
            for &pos in &[0, len / 2, len - 1] {
                buf[pos] = WIRE_MAGIC;
                assert_eq!(
                    find_magic(&buf[..len]),
                    Some(pos),
                    "failed at len={len}, pos={pos}"
                );
                assert_eq!(
                    find_magic_swar(&buf[..len]),
                    Some(pos),
                    "swar failed at len={len}, pos={pos}"
                );
                buf[pos] = 0xAA;
            }
        }
    }

    #[test]
    fn test_stream_resync_recovery_from_noise() {
        let payload = b"Resynchronized frame payload";
        let header = WireHeader {
            profile: OptimizationProfile::Realtime,
            flags: WireFlags::default(),
            payload_len: payload.len(),
            schema_hash: None,
        };

        let mut frame_buf = [0u8; 128];
        let frame_len = pack_frame(&header, payload, &mut frame_buf).unwrap();

        // Construct noisy stream: 47 bytes of garbage + false magic + frame
        let mut stream = [0u8; 256];
        for (i, b) in stream[..47].iter_mut().enumerate() {
            *b = (i * 17 + 3) as u8;
        }
        // Inject false magic followed by garbage
        stream[15] = WIRE_MAGIC;
        stream[16] = 0xFF; // Invalid version

        // Copy valid frame at offset 47
        stream[47..47 + frame_len].copy_from_slice(&frame_buf[..frame_len]);

        let (skipped, recovered) =
            resync_frame(&stream[..47 + frame_len]).expect("must recover frame");
        assert_eq!(skipped, 47);
        assert_eq!(recovered.payload, payload);
        assert_eq!(recovered.frame_len, frame_len);
    }

    #[test]
    fn test_stream_resync_parser_accumulated_stats() {
        let payload1 = b"Frame 1";
        let payload2 = b"Frame 2";
        let hdr = WireHeader {
            profile: OptimizationProfile::Balanced,
            flags: WireFlags::default(),
            payload_len: payload1.len(),
            schema_hash: None,
        };

        let mut b1 = [0u8; 64];
        let l1 = pack_frame(&hdr, payload1, &mut b1).unwrap();

        let mut b2 = [0u8; 64];
        let l2 = pack_frame(&hdr, payload2, &mut b2).unwrap();

        // Stream: Noise (20B) + Frame 1 (l1) + Noise (10B) + Frame 2 (l2)
        let mut stream = [0u8; 200];
        let mut cur = 0;
        // Noise 1
        stream[cur..cur + 20].fill(0xEE);
        cur += 20;
        // Frame 1
        stream[cur..cur + l1].copy_from_slice(&b1[..l1]);
        cur += l1;
        // Noise 2
        stream[cur..cur + 10].fill(0x77);
        cur += 10;
        // Frame 2
        stream[cur..cur + l2].copy_from_slice(&b2[..l2]);
        cur += l2;

        let total_stream = &stream[..cur];
        let mut parser = StreamResyncParser::new();

        // Read 1
        let (consumed1, f1) = parser.parse_next(total_stream).expect("must parse frame 1");
        assert_eq!(consumed1, 20 + l1);
        assert_eq!(f1.payload, payload1);

        // Read 2
        let remaining = &total_stream[consumed1..];
        let (consumed2, f2) = parser.parse_next(remaining).expect("must parse frame 2");
        assert_eq!(consumed2, 10 + l2);
        assert_eq!(f2.payload, payload2);

        let stats = parser.stats();
        assert_eq!(stats.frames_decoded, 2);
        assert_eq!(stats.bytes_discarded, 30);
        assert_eq!(stats.resync_events, 2);
    }

    #[test]
    fn test_resync_forged_magic_huge_length_never_stalls() {
        let valid_payload = b"Valid Payload";
        let hdr = WireHeader {
            profile: OptimizationProfile::Direct,
            flags: WireFlags::default(),
            payload_len: valid_payload.len(),
            schema_hash: None,
        };
        let mut valid_buf = [0u8; 64];
        let valid_len = pack_frame(&hdr, valid_payload, &mut valid_buf).unwrap();

        let mut stream = [0u8; 128];
        stream[0] = WIRE_MAGIC;
        stream[1] = WIRE_VERSION_1;
        stream[2] = 0x00;
        let _ = crate::varint::encode_prefix_varint(100 * 1024 * 1024, &mut stream[3..]);
        stream[15..15 + valid_len].copy_from_slice(&valid_buf[..valid_len]);

        let mut parser = StreamResyncParser::new();
        let res = parser.parse_next(&stream[..15 + valid_len]);
        assert!(
            res.is_some(),
            "Parser must not stall on forged huge payload"
        );
        let (consumed, frame) = res.unwrap();
        assert_eq!(frame.payload, valid_payload);
        assert_eq!(consumed, 15 + valid_len);
    }
}
