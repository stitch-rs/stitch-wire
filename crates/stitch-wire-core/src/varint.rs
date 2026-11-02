//! Branchless PrefixVarint integer encoding.
//!
//! Unlike LEB128, which consumes an extra bit in each byte as a continuation flag
//! and forces an unpredictable branch in sequential loops, PrefixVarint stores the
//! byte count as a series of trailing/leading zeros or ones in the first byte.

use crate::error::WireError;

/// Returns the number of bytes required to encode `value` as a PrefixVarint.
#[inline]
pub const fn prefix_varint_len(value: u64) -> usize {
    if value < (1 << 7) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 21) {
        3
    } else if value < (1 << 28) {
        4
    } else if value < (1 << 35) {
        5
    } else if value < (1 << 42) {
        6
    } else if value < (1 << 49) {
        7
    } else if value < (1 << 56) {
        8
    } else {
        9
    }
}

/// Encodes a `u64` into a prefix-varint byte buffer, returning the number of bytes written.
/// Buffer must have at least 9 bytes available.
#[inline]
pub fn encode_prefix_varint(value: u64, buf: &mut [u8]) -> usize {
    if value < (1 << 7) {
        buf[0] = (value as u8) << 1 | 0x01;
        1
    } else if value < (1 << 14) {
        let v = (value << 2) | 0x02;
        buf[0] = v as u8;
        buf[1] = (v >> 8) as u8;
        2
    } else if value < (1 << 21) {
        let v = (value << 3) | 0x04;
        buf[0] = v as u8;
        buf[1] = (v >> 8) as u8;
        buf[2] = (v >> 16) as u8;
        3
    } else if value < (1 << 28) {
        let v = (value << 4) | 0x08;
        buf[0] = v as u8;
        buf[1] = (v >> 8) as u8;
        buf[2] = (v >> 16) as u8;
        buf[3] = (v >> 24) as u8;
        4
    } else if value < (1 << 35) {
        let v = (value << 5) | 0x10;
        buf[0] = v as u8;
        buf[1] = (v >> 8) as u8;
        buf[2] = (v >> 16) as u8;
        buf[3] = (v >> 24) as u8;
        buf[4] = (v >> 32) as u8;
        5
    } else if value < (1 << 42) {
        let v = (value << 6) | 0x20;
        buf[0] = v as u8;
        buf[1] = (v >> 8) as u8;
        buf[2] = (v >> 16) as u8;
        buf[3] = (v >> 24) as u8;
        buf[4] = (v >> 32) as u8;
        buf[5] = (v >> 40) as u8;
        6
    } else if value < (1 << 49) {
        let v = (value << 7) | 0x40;
        buf[0] = v as u8;
        buf[1] = (v >> 8) as u8;
        buf[2] = (v >> 16) as u8;
        buf[3] = (v >> 24) as u8;
        buf[4] = (v >> 32) as u8;
        buf[5] = (v >> 40) as u8;
        buf[6] = (v >> 48) as u8;
        7
    } else if value < (1 << 56) {
        buf[0] = 0x80;
        buf[1] = value as u8;
        buf[2] = (value >> 8) as u8;
        buf[3] = (value >> 16) as u8;
        buf[4] = (value >> 24) as u8;
        buf[5] = (value >> 32) as u8;
        buf[6] = (value >> 40) as u8;
        buf[7] = (value >> 48) as u8;
        8
    } else {
        buf[0] = 0x00;
        buf[1..9].copy_from_slice(&value.to_le_bytes());
        9
    }
}

/// Decodes a `u64` from a prefix-varint byte buffer, returning `(value, bytes_consumed)`.
#[inline]
pub fn decode_prefix_varint(buf: &[u8]) -> Result<(u64, usize), WireError> {
    if buf.is_empty() {
        return Err(WireError::UnexpectedEof {
            required: 1,
            available: 0,
        });
    }

    let b0 = buf[0];
    if b0 & 0x01 != 0 {
        return Ok(((b0 >> 1) as u64, 1));
    }

    let trailing = b0.trailing_zeros();
    let len = (trailing as usize) + 1;

    if b0 == 0x00 {
        if buf.len() < 9 {
            return Err(WireError::UnexpectedEof {
                required: 9,
                available: buf.len(),
            });
        }
        let val = u64::from_le_bytes(buf[1..9].try_into().unwrap());
        return Ok((val, 9));
    }

    if buf.len() < len {
        return Err(WireError::UnexpectedEof {
            required: len,
            available: buf.len(),
        });
    }

    if len == 8 {
        let mut bytes = [0u8; 8];
        bytes[..7].copy_from_slice(&buf[1..8]);
        let val = u64::from_le_bytes(bytes);
        return Ok((val, 8));
    }

    let mut val = 0u64;
    for (i, &byte) in buf.iter().enumerate().take(len) {
        val |= (byte as u64) << (i * 8);
    }
    val >>= len;
    Ok((val, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_varint_roundtrip() {
        let cases = [
            0u64,
            1,
            127,
            128,
            16383,
            16384,
            2097151,
            2097152,
            u32::MAX as u64,
            u64::MAX - 1,
            u64::MAX,
        ];
        let mut buf = [0u8; 16];
        for &val in &cases {
            let n = encode_prefix_varint(val, &mut buf);
            let (decoded, consumed) = decode_prefix_varint(&buf[..n]).unwrap();
            assert_eq!(n, consumed, "consumed length mismatch for {}", val);
            assert_eq!(val, decoded, "value mismatch for {}", val);
        }
    }
}
