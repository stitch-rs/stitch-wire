//! CBP Frame framing structures according to Version 1 Axiom.

use crate::crc::crc32_castagnoli;
use crate::error::WireError;
use crate::varint::{decode_prefix_varint, encode_prefix_varint};

/// Canonical Magic byte for Compact Binary Protocol (`0xCB`).
pub const WIRE_MAGIC: u8 = 0xCB;

/// Version 1 identifier.
pub const WIRE_VERSION_1: u8 = 0x01;

/// Maximum permitted payload length for a single CBP frame (64 MiB).
/// Protects against malicious allocation attacks and length overflow vulnerabilities.
pub const MAX_FRAME_PAYLOAD_LEN: usize = 64 * 1024 * 1024;

/// Maximum possible header size in bytes:
/// 1B (Magic) + 1B (Version) + 1B (Flags) + 9B (Max PrefixVarint u64) + 8B (SchemaHash) = 20B.
pub const MAX_HEADER_SIZE: usize = 20;

/// Maximum total wire frame length:
/// MAX_HEADER_SIZE + MAX_FRAME_PAYLOAD_LEN + 4B (CRC32).
pub const MAX_FRAME_TOTAL_LEN: usize = MAX_HEADER_SIZE + MAX_FRAME_PAYLOAD_LEN + 4;

/// Helper function to safely calculate total frame length: `header_len + payload_len + 4`.
/// Returns `Err(WireError::FrameTooLarge)` or `Err(WireError::PayloadDecodeError)` on overflow.
#[inline]
pub fn checked_frame_total_len(header_len: usize, payload_len: usize) -> Result<usize, WireError> {
    if payload_len > MAX_FRAME_PAYLOAD_LEN {
        return Err(WireError::FrameTooLarge {
            size: payload_len as u64,
            limit: MAX_FRAME_PAYLOAD_LEN,
        });
    }

    let with_payload = header_len
        .checked_add(payload_len)
        .ok_or(WireError::PayloadDecodeError)?;
    let total = with_payload
        .checked_add(4)
        .ok_or(WireError::PayloadDecodeError)?;
    Ok(total)
}

/// Layered optimization profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OptimizationProfile {
    /// -O0: Direct zero-copy without transformations.
    Direct = 0b00,
    /// -O1: Realtime sub-microsecond SIMD bit-packing and prefix varints.
    Realtime = 0b01,
    /// -O2: Balanced delta-encoding, PFOR, and RLE.
    Balanced = 0b10,
    /// -O3: Maximum density (columnar SoA, Elias-Fano, dictionary).
    MaxDensity = 0b11,
}

impl OptimizationProfile {
    /// Converts a 2-bit value into an `OptimizationProfile`.
    #[inline]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => Self::Direct,
            0b01 => Self::Realtime,
            0b10 => Self::Balanced,
            _ => Self::MaxDensity,
        }
    }
}

/// Bitwise frame attribute flags adhering to the Scrooge Systems Mindset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WireFlags {
    /// Payload is compressed using profile transforms.
    pub is_compressed: bool,
    /// Payload is organized into columnar or chunked blocks.
    pub is_chunked: bool,
    /// Header includes a 64-bit schema fingerprint.
    pub has_schema_hash: bool,
    /// State channel marker: retain last valid state for subsequent consumers.
    pub retain_last: bool,
    /// Transport requires reliable delivery acknowledgment.
    pub requires_ack: bool,
    /// Frame is a system heartbeat/ping datagram.
    pub is_heartbeat: bool,
}

impl WireFlags {
    /// Creates a new WireFlags with baseline parameters.
    #[inline]
    pub const fn new(is_compressed: bool, is_chunked: bool, has_schema_hash: bool) -> Self {
        Self {
            is_compressed,
            is_chunked,
            has_schema_hash,
            retain_last: false,
            requires_ack: false,
            is_heartbeat: false,
        }
    }
    /// Bit 0: Payload is compressed.
    pub const FLAG_COMPRESSED: u8 = 0x01;
    /// Bit 1: Payload is chunked/fragmented.
    pub const FLAG_CHUNKED: u8 = 0x02;
    /// Bit 2: Includes schema fingerprint.
    pub const FLAG_SCHEMA_HASH: u8 = 0x04;
    /// Bit 3: Retain last state snapshot.
    pub const FLAG_RETAIN_LAST: u8 = 0x08;
    /// Bit 4: Requires delivery ACK.
    pub const FLAG_REQUIRES_ACK: u8 = 0x10;
    /// Bit 5: Heartbeat packet.
    pub const FLAG_HEARTBEAT: u8 = 0x20;

    /// Converts flags into an 8-bit byte representation.
    #[inline]
    pub const fn to_bits(&self) -> u8 {
        let mut bits = 0u8;
        if self.is_compressed {
            bits |= Self::FLAG_COMPRESSED;
        }
        if self.is_chunked {
            bits |= Self::FLAG_CHUNKED;
        }
        if self.has_schema_hash {
            bits |= Self::FLAG_SCHEMA_HASH;
        }
        if self.retain_last {
            bits |= Self::FLAG_RETAIN_LAST;
        }
        if self.requires_ack {
            bits |= Self::FLAG_REQUIRES_ACK;
        }
        if self.is_heartbeat {
            bits |= Self::FLAG_HEARTBEAT;
        }
        bits
    }

    /// Parses flags from an 8-bit byte representation.
    #[inline]
    pub const fn from_bits(bits: u8) -> Self {
        Self {
            is_compressed: (bits & Self::FLAG_COMPRESSED) != 0,
            is_chunked: (bits & Self::FLAG_CHUNKED) != 0,
            has_schema_hash: (bits & Self::FLAG_SCHEMA_HASH) != 0,
            retain_last: (bits & Self::FLAG_RETAIN_LAST) != 0,
            requires_ack: (bits & Self::FLAG_REQUIRES_ACK) != 0,
            is_heartbeat: (bits & Self::FLAG_HEARTBEAT) != 0,
        }
    }
}

/// In-memory representation of a CBP Frame Header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireHeader {
    /// Selected optimization profile.
    pub profile: OptimizationProfile,
    /// Frame flags.
    pub flags: WireFlags,
    /// Payload length in bytes.
    pub payload_len: usize,
    /// Optional schema fingerprint (xxHash64).
    pub schema_hash: Option<u64>,
}

impl WireHeader {
    /// Serializes this frame header into `buf`. Returns bytes written.
    pub fn write_into(&self, buf: &mut [u8]) -> Result<usize, WireError> {
        let has_schema = self.schema_hash.is_some();
        let mut flags = self.flags;
        flags.has_schema_hash = has_schema;

        let varint_len = crate::varint::prefix_varint_len(self.payload_len as u64);
        let schema_len = if has_schema { 8 } else { 0 };
        let required_header_len = 3 + varint_len + schema_len;

        if buf.len() < required_header_len {
            return Err(WireError::UnexpectedEof {
                required: required_header_len,
                available: buf.len(),
            });
        }

        buf[0] = WIRE_MAGIC;
        buf[1] = WIRE_VERSION_1;

        let profile_bits = (self.profile as u8) & 0b11;
        let flags_bits = (flags.to_bits() & 0b0011_1111) << 2;
        buf[2] = profile_bits | flags_bits;

        let mut offset = 3;
        let written_varint = encode_prefix_varint(self.payload_len as u64, &mut buf[offset..]);
        offset += written_varint;

        if let Some(hash) = self.schema_hash {
            buf[offset..offset + 8].copy_from_slice(&hash.to_le_bytes());
            offset += 8;
        }

        Ok(offset)
    }

    /// Parses a frame header from a byte slice. Returns `(WireHeader, bytes_consumed)`.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), WireError> {
        if buf.len() < 3 {
            return Err(WireError::UnexpectedEof {
                required: 3,
                available: buf.len(),
            });
        }

        if buf[0] != WIRE_MAGIC {
            return Err(WireError::InvalidMagic(buf[0]));
        }
        if buf[1] != WIRE_VERSION_1 {
            return Err(WireError::UnsupportedVersion(buf[1]));
        }

        let byte2 = buf[2];

        let profile = OptimizationProfile::from_bits(byte2 & 0b11);
        let flag_bits = (byte2 >> 2) & 0b0011_1111;
        let flags = WireFlags::from_bits(flag_bits);

        let mut offset = 3;
        let (raw_payload_len, varint_len) = decode_prefix_varint(&buf[offset..])?;
        offset += varint_len;

        let payload_len =
            usize::try_from(raw_payload_len).map_err(|_| WireError::FrameTooLarge {
                size: raw_payload_len,
                limit: MAX_FRAME_PAYLOAD_LEN,
            })?;

        if payload_len > MAX_FRAME_PAYLOAD_LEN {
            return Err(WireError::FrameTooLarge {
                size: raw_payload_len,
                limit: MAX_FRAME_PAYLOAD_LEN,
            });
        }

        let mut schema_hash = None;
        if flags.has_schema_hash {
            if buf.len() < offset + 8 {
                return Err(WireError::UnexpectedEof {
                    required: offset + 8,
                    available: buf.len(),
                });
            }
            schema_hash = Some(u64::from_le_bytes(
                buf[offset..offset + 8].try_into().unwrap(),
            ));
            offset += 8;
        }

        Ok((
            Self {
                profile,
                flags,
                payload_len,
                schema_hash,
            },
            offset,
        ))
    }
}

/// Packs an entire CBP frame (Header + Payload + CRC32 Footer) into `out_buf`.
pub fn pack_frame(
    header: &WireHeader,
    payload: &[u8],
    out_buf: &mut [u8],
) -> Result<usize, WireError> {
    if payload.len() > MAX_FRAME_PAYLOAD_LEN {
        return Err(WireError::FrameTooLarge {
            size: payload.len() as u64,
            limit: MAX_FRAME_PAYLOAD_LEN,
        });
    }

    let mut effective_header = header.clone();
    effective_header.payload_len = payload.len();
    effective_header.flags.has_schema_hash = effective_header.schema_hash.is_some();

    let varint_len = crate::varint::prefix_varint_len(payload.len() as u64);
    let schema_len = if effective_header.schema_hash.is_some() {
        8
    } else {
        0
    };
    let header_len = 3 + varint_len + schema_len;
    let total_len = checked_frame_total_len(header_len, payload.len())?;

    if out_buf.len() < total_len {
        return Err(WireError::UnexpectedEof {
            required: total_len,
            available: out_buf.len(),
        });
    }

    let written_header_len = effective_header.write_into(out_buf)?;
    debug_assert_eq!(written_header_len, header_len);

    out_buf[header_len..header_len + payload.len()].copy_from_slice(payload);

    let crc = crc32_castagnoli(&out_buf[..header_len + payload.len()]);
    out_buf[header_len + payload.len()..total_len].copy_from_slice(&crc.to_le_bytes());

    Ok(total_len)
}

/// Unpacks and validates a CBP frame from `buf`. Returns `(WireHeader, payload_slice)`.
pub fn unpack_frame(buf: &[u8]) -> Result<(WireHeader, &[u8]), WireError> {
    let (header, header_len) = WireHeader::parse(buf)?;
    let expected_total = checked_frame_total_len(header_len, header.payload_len)?;

    if buf.len() < expected_total {
        return Err(WireError::UnexpectedEof {
            required: expected_total,
            available: buf.len(),
        });
    }

    let payload = &buf[header_len..header_len + header.payload_len];
    let expected_crc =
        u32::from_le_bytes(buf[expected_total - 4..expected_total].try_into().unwrap());
    let actual_crc = crc32_castagnoli(&buf[..header_len + header.payload_len]);

    if expected_crc != actual_crc {
        return Err(WireError::ChecksumMismatch {
            expected: expected_crc,
            actual: actual_crc,
        });
    }

    Ok((header, payload))
}

/// A zero-allocation, scatter-gather vectored representation of a serialized CBP frame.
///
/// Encodes the header into a tiny stack buffer and borrows the payload directly,
/// computing the CRC32 checksum across both slices without intermediate memory allocation
/// or contiguous buffer assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectoredFrame<'a> {
    header_buf: [u8; MAX_HEADER_SIZE],
    header_len: usize,
    payload: &'a [u8],
    crc_buf: [u8; 4],
}

impl<'a> VectoredFrame<'a> {
    /// Returns the serialized frame header slice.
    #[inline]
    pub fn header(&self) -> &[u8] {
        &self.header_buf[..self.header_len]
    }

    /// Returns the borrowed payload slice.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Returns the 4-byte little-endian CRC32 Castagnoli checksum footer bytes.
    #[inline]
    pub fn crc_bytes(&self) -> &[u8; 4] {
        &self.crc_buf
    }

    /// Returns the calculated CRC32 checksum as a `u32`.
    #[inline]
    pub fn crc(&self) -> u32 {
        u32::from_le_bytes(self.crc_buf)
    }

    /// Returns the total wire length of the frame in bytes (`header_len + payload.len() + 4`).
    #[inline]
    pub fn total_len(&self) -> usize {
        self.header_len
            .checked_add(self.payload.len())
            .and_then(|v| v.checked_add(4))
            .expect("VectoredFrame total length overflow")
    }

    /// Returns the 3 scatter-gather byte slices `[Header, Payload, CRC32]`.
    #[inline]
    pub fn slices(&self) -> [&[u8]; 3] {
        [self.header(), self.payload, &self.crc_buf]
    }

    /// Returns the slices as standard `std::io::IoSlice` references for direct `writev` dispatch.
    #[cfg(feature = "std")]
    #[inline]
    pub fn io_slices(&self) -> [std::io::IoSlice<'_>; 3] {
        [
            std::io::IoSlice::new(self.header()),
            std::io::IoSlice::new(self.payload),
            std::io::IoSlice::new(&self.crc_buf),
        ]
    }

    /// Copies the entire vectored frame contiguously into `dst`. Returns total bytes written.
    #[inline]
    pub fn copy_to_slice(&self, dst: &mut [u8]) -> Result<usize, WireError> {
        let total = self.total_len();
        if dst.len() < total {
            return Err(WireError::UnexpectedEof {
                required: total,
                available: dst.len(),
            });
        }

        let h_len = self.header_len;
        let p_len = self.payload.len();

        dst[..h_len].copy_from_slice(self.header());
        dst[h_len..h_len + p_len].copy_from_slice(self.payload);
        dst[h_len + p_len..total].copy_from_slice(&self.crc_buf);

        Ok(total)
    }
}

/// Encodes a CBP frame in scatter-gather vectored mode with zero payload copying and zero heap allocations.
///
/// Prepares a stack-allocated header and calculates the CRC32-C checksum across both the header
/// and the borrowed payload slice using `crc32_castagnoli_slices`.
pub fn pack_frame_vectored<'a>(
    header: &WireHeader,
    payload: &'a [u8],
) -> Result<VectoredFrame<'a>, WireError> {
    if payload.len() > MAX_FRAME_PAYLOAD_LEN {
        return Err(WireError::FrameTooLarge {
            size: payload.len() as u64,
            limit: MAX_FRAME_PAYLOAD_LEN,
        });
    }

    let mut header_buf = [0u8; MAX_HEADER_SIZE];
    let mut effective_header = header.clone();
    effective_header.payload_len = payload.len();
    let header_len = effective_header.write_into(&mut header_buf)?;

    let _ = checked_frame_total_len(header_len, payload.len())?;

    let crc = crate::crc::crc32_castagnoli_slices(&[&header_buf[..header_len], payload]);

    Ok(VectoredFrame {
        header_buf,
        header_len,
        payload,
        crc_buf: crc.to_le_bytes(),
    })
}

/// A zero-copy borrowed view of an unpacked CBP frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameView<'a> {
    /// Parsed frame header.
    pub header: WireHeader,
    /// Direct borrowed slice into the frame payload.
    pub payload: &'a [u8],
    /// Verified Castagnoli CRC32 checksum from the footer.
    pub crc: u32,
    /// Total wire bytes consumed by this frame (`header_len + payload_len + 4`).
    pub frame_len: usize,
}

/// A zero-allocation, cursor-based streaming reader that yields successive frames from a borrowed slice.
///
/// Efficiently processes multi-frame buffers (e.g. TCP buffers, IPC shared memory, ring buffers)
/// with zero heap allocations and zero memory copies.
#[derive(Debug, Clone)]
pub struct FrameReader<'a> {
    buffer: &'a [u8],
    cursor: usize,
}

impl<'a> FrameReader<'a> {
    /// Creates a new `FrameReader` over the given borrowed buffer.
    #[inline]
    pub const fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, cursor: 0 }
    }

    /// Returns the slice of unconsumed bytes remaining in the buffer.
    #[inline]
    pub fn remaining(&self) -> &'a [u8] {
        &self.buffer[self.cursor..]
    }

    /// Returns the number of bytes consumed so far.
    #[inline]
    pub const fn consumed(&self) -> usize {
        self.cursor
    }

    /// Returns `true` if all bytes in the buffer have been consumed.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.cursor >= self.buffer.len()
    }

    /// Decodes and verifies the next CBP frame from the buffer, advancing the cursor.
    ///
    /// - Returns `Ok(Some(frame))` if a valid frame was unpacked and verified.
    /// - Returns `Ok(None)` if all bytes have been consumed (`remaining().is_empty()`).
    /// - Returns `Err(WireError::UnexpectedEof { .. })` if the remaining buffer contains a partial frame.
    /// - Returns `Err(...)` if the magic byte, version, or CRC32 checksum is invalid.
    pub fn next_frame(&mut self) -> Result<Option<FrameView<'a>>, WireError> {
        let remaining = self.remaining();
        if remaining.is_empty() {
            return Ok(None);
        }

        let (header, header_len) = WireHeader::parse(remaining)?;
        let expected_total = checked_frame_total_len(header_len, header.payload_len)?;

        if remaining.len() < expected_total {
            return Err(WireError::UnexpectedEof {
                required: expected_total,
                available: remaining.len(),
            });
        }

        let payload = &remaining[header_len..header_len + header.payload_len];
        let expected_crc = u32::from_le_bytes(
            remaining[expected_total - 4..expected_total]
                .try_into()
                .unwrap(),
        );
        let actual_crc =
            crate::crc::crc32_castagnoli(&remaining[..header_len + header.payload_len]);

        if expected_crc != actual_crc {
            return Err(WireError::ChecksumMismatch {
                expected: expected_crc,
                actual: actual_crc,
            });
        }

        self.cursor += expected_total;

        Ok(Some(FrameView {
            header,
            payload,
            crc: expected_crc,
            frame_len: expected_total,
        }))
    }
}

impl<'a> Iterator for FrameReader<'a> {
    type Item = Result<FrameView<'a>, WireError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self.next_frame() {
            Ok(Some(view)) => Some(Ok(view)),
            Ok(None) => None,
            Err(e) => {
                // Advance cursor to end on error to terminate iterator safely
                self.cursor = self.buffer.len();
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_pack_unpack_roundtrip() {
        let payload = b"Hello CBP Engine from Rust!";
        let header = WireHeader {
            profile: OptimizationProfile::Balanced,
            flags: WireFlags::new(true, false, true),
            payload_len: payload.len(),
            schema_hash: Some(0xDEADBEEFCAFE1234),
        };

        let mut storage = [0u8; 128];
        let total = pack_frame(&header, payload, &mut storage).unwrap();

        let (unpacked_hdr, unpacked_payload) = unpack_frame(&storage[..total]).unwrap();
        assert_eq!(unpacked_hdr, header);
        assert_eq!(unpacked_payload, payload);
    }

    #[test]
    fn test_vectored_frame_parity_with_pack_frame() {
        let payload = b"Vectored scatter-gather payload";
        let header = WireHeader {
            profile: OptimizationProfile::Realtime,
            flags: WireFlags::new(true, false, true),
            payload_len: payload.len(),
            schema_hash: Some(0xA1B2C3D4E5F60718),
        };

        let mut contiguous = [0u8; 128];
        let packed_len = pack_frame(&header, payload, &mut contiguous).unwrap();

        let vectored = pack_frame_vectored(&header, payload).unwrap();
        assert_eq!(vectored.total_len(), packed_len);
        assert_eq!(vectored.header(), &contiguous[..vectored.header().len()]);
        assert_eq!(vectored.payload(), payload);
        assert_eq!(
            vectored.crc_bytes(),
            &contiguous[packed_len - 4..packed_len]
        );

        let mut copied = [0u8; 128];
        let copied_len = vectored.copy_to_slice(&mut copied).unwrap();
        assert_eq!(&copied[..copied_len], &contiguous[..packed_len]);
    }

    #[test]
    fn test_frame_reader_multi_frame_stream() {
        let payload1 = b"Frame number 1";
        let payload2 = b"Frame number 2: longer payload contents";
        let payload3 = b"Frame number 3: end of sequence";

        let hdr1 = WireHeader {
            profile: OptimizationProfile::Direct,
            flags: WireFlags::default(),
            payload_len: payload1.len(),
            schema_hash: None,
        };
        let hdr2 = WireHeader {
            profile: OptimizationProfile::Realtime,
            flags: WireFlags::new(true, false, false),
            payload_len: payload2.len(),
            schema_hash: None,
        };
        let hdr3 = WireHeader {
            profile: OptimizationProfile::MaxDensity,
            flags: WireFlags::new(true, true, true),
            payload_len: payload3.len(),
            schema_hash: Some(0x1234),
        };

        let mut buffer = [0u8; 512];
        let mut offset = 0;
        offset += pack_frame(&hdr1, payload1, &mut buffer[offset..]).unwrap();
        offset += pack_frame(&hdr2, payload2, &mut buffer[offset..]).unwrap();
        offset += pack_frame(&hdr3, payload3, &mut buffer[offset..]).unwrap();

        let total_stream = &buffer[..offset];

        let mut reader = FrameReader::new(total_stream);

        let f1 = reader.next_frame().unwrap().expect("frame 1 must exist");
        assert_eq!(f1.payload, payload1);
        assert_eq!(f1.header.profile, OptimizationProfile::Direct);

        let f2 = reader.next_frame().unwrap().expect("frame 2 must exist");
        assert_eq!(f2.payload, payload2);
        assert_eq!(f2.header.profile, OptimizationProfile::Realtime);

        let f3 = reader.next_frame().unwrap().expect("frame 3 must exist");
        assert_eq!(f3.payload, payload3);
        assert_eq!(f3.header.profile, OptimizationProfile::MaxDensity);

        assert!(
            reader.next_frame().unwrap().is_none(),
            "stream must be exhausted"
        );
        assert!(reader.is_empty());
        assert_eq!(reader.consumed(), offset);
    }

    #[test]
    fn test_frame_reader_partial_frame_unexpected_eof() {
        let payload = b"Partial frame testing payload";
        let header = WireHeader {
            profile: OptimizationProfile::Balanced,
            flags: WireFlags::default(),
            payload_len: payload.len(),
            schema_hash: None,
        };

        let mut buf = [0u8; 128];
        let total = pack_frame(&header, payload, &mut buf).unwrap();

        // Truncate by 5 bytes
        let truncated = &buf[..total - 5];
        let mut reader = FrameReader::new(truncated);
        let err = reader.next_frame().unwrap_err();

        match err {
            WireError::UnexpectedEof {
                required,
                available,
            } => {
                assert_eq!(required, total);
                assert_eq!(available, total - 5);
            }
            other => panic!("expected UnexpectedEof, got {:?}", other),
        }
    }
    #[test]
    fn test_corrupted_crc_detection() {
        let payload = b"Sensitive payload";
        let header = WireHeader {
            profile: OptimizationProfile::Direct,
            flags: WireFlags::default(),
            payload_len: payload.len(),
            schema_hash: None,
        };

        let mut storage = [0u8; 64];
        let total = pack_frame(&header, payload, &mut storage).unwrap();

        // Corrupt single payload byte
        storage[5] ^= 0xFF;

        let res = unpack_frame(&storage[..total]);
        assert!(matches!(res, Err(WireError::ChecksumMismatch { .. })));
    }

    #[test]
    fn test_frame_header_flags_parsing() {
        let mut buf = [0u8; 32];
        buf[0] = WIRE_MAGIC;
        buf[1] = WIRE_VERSION_1;
        // Profile Realtime (1) + RetainLast (bit 3 -> 0x08 << 2 = 0x20)
        buf[2] = 1 | (0x08 << 2);
        // Prefix varint 0 (1-byte varint representation where LSB is 1)
        buf[3] = 1;
        let (hdr, len) = WireHeader::parse(&buf).unwrap();
        assert_eq!(len, 4);
        assert_eq!(hdr.profile, OptimizationProfile::Realtime);
        assert!(hdr.flags.retain_last);
        assert!(!hdr.flags.is_compressed);
    }

    #[test]
    fn test_frame_schema_flag_and_hash_normalization() {
        let payload = b"Schema flag normalization test";
        // Case 1: has_schema_hash: false, but schema_hash: Some(0x1234)
        // pack_frame/write_into must normalize has_schema_hash to true and preserve the schema hash
        let header1 = WireHeader {
            profile: OptimizationProfile::Realtime,
            flags: WireFlags::new(false, false, false),
            payload_len: payload.len(),
            schema_hash: Some(0x1234),
        };
        let mut buf1 = [0u8; 128];
        let total1 = pack_frame(&header1, payload, &mut buf1).unwrap();
        let (unpacked1, _) = unpack_frame(&buf1[..total1]).unwrap();
        assert!(unpacked1.flags.has_schema_hash);
        assert_eq!(unpacked1.schema_hash, Some(0x1234));

        // Case 2: has_schema_hash: true, but schema_hash: None
        // pack_frame/write_into must normalize has_schema_hash to false
        let header2 = WireHeader {
            profile: OptimizationProfile::Realtime,
            flags: WireFlags::new(false, false, true),
            payload_len: payload.len(),
            schema_hash: None,
        };
        let mut buf2 = [0u8; 128];
        let total2 = pack_frame(&header2, payload, &mut buf2).unwrap();
        let (unpacked2, _) = unpack_frame(&buf2[..total2]).unwrap();
        assert!(!unpacked2.flags.has_schema_hash);
        assert_eq!(unpacked2.schema_hash, None);
    }

    #[test]
    fn test_minimal_empty_frame_roundtrip() {
        let header = WireHeader {
            profile: OptimizationProfile::Direct,
            flags: WireFlags::default(),
            payload_len: 0,
            schema_hash: None,
        };
        let mut buf = [0u8; 32];
        let total = pack_frame(&header, &[], &mut buf).unwrap();
        // 3 bytes (Magic, Version, Flags) + 1 byte (PrefixVarint 0) + 0 bytes payload + 4 bytes CRC = 8 bytes
        assert_eq!(total, 8);

        let (unpacked, payload) = unpack_frame(&buf[..total]).unwrap();
        assert_eq!(unpacked.payload_len, 0);
        assert_eq!(payload.len(), 0);
        assert!(!unpacked.flags.has_schema_hash);
        assert_eq!(unpacked.schema_hash, None);
    }

    #[test]
    fn test_all_wire_flags_roundtrip() {
        for compressed in [false, true] {
            for chunked in [false, true] {
                for schema in [false, true] {
                    for retain in [false, true] {
                        for ack in [false, true] {
                            for heartbeat in [false, true] {
                                let flags = WireFlags {
                                    is_compressed: compressed,
                                    is_chunked: chunked,
                                    has_schema_hash: schema,
                                    retain_last: retain,
                                    requires_ack: ack,
                                    is_heartbeat: heartbeat,
                                };
                                let header = WireHeader {
                                    profile: OptimizationProfile::Realtime,
                                    flags,
                                    payload_len: 4,
                                    schema_hash: if schema { Some(0xCAFE_BABE) } else { None },
                                };
                                let mut buf = [0u8; 64];
                                let written = header.write_into(&mut buf).unwrap();
                                let (parsed, consumed) =
                                    WireHeader::parse(&buf[..written]).unwrap();
                                assert_eq!(consumed, written);
                                assert_eq!(parsed.profile, header.profile);
                                assert_eq!(parsed.flags.is_compressed, flags.is_compressed);
                                assert_eq!(parsed.flags.is_chunked, flags.is_chunked);
                                assert_eq!(parsed.flags.has_schema_hash, flags.has_schema_hash);
                                assert_eq!(parsed.flags.retain_last, flags.retain_last);
                                assert_eq!(parsed.flags.requires_ack, flags.requires_ack);
                                assert_eq!(parsed.flags.is_heartbeat, flags.is_heartbeat);
                            }
                        }
                    }
                }
            }
        }
    }
}
