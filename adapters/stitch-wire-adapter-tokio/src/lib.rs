//! Tokio async framing codec and stream adapter for the Stitch Wire protocol.
//!
//! Implements [`tokio_util::codec::Decoder`] and [`tokio_util::codec::Encoder`]
//! for bidirectional framing of continuous byte streams.

use bytes::{Buf, BufMut, BytesMut};
use std::io;
use stitch_wire_core::error::WireError;
use stitch_wire_core::frame::{
    OptimizationProfile, WireFlags, WireHeader, checked_frame_total_len, pack_frame, unpack_frame,
};
use stitch_wire_core::resync::find_magic_swar;
use tokio_util::codec::{Decoder, Encoder};

/// Errors that can occur during Tokio async framing operations.
#[derive(Debug)]
pub enum TokioWireError {
    /// Internal Wire protocol or framing error.
    Wire(WireError),
    /// Underlying I/O error.
    Io(io::Error),
}

impl From<WireError> for TokioWireError {
    fn from(e: WireError) -> Self {
        Self::Wire(e)
    }
}

impl From<io::Error> for TokioWireError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl core::fmt::Display for TokioWireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire(e) => write!(f, "Wire protocol error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for TokioWireError {}

/// Tokio framing codec for `stitch-wire` transport streams.
///
/// Handles stream framing, Castagnoli CRC32 validation, and SWAR resynchronization.
#[derive(Debug, Clone)]
pub struct StitchWireCodec {
    /// Optimization profile used when encoding outgoing frames.
    pub profile: OptimizationProfile,
    /// Default flags used for outgoing frames.
    pub flags: WireFlags,
}

impl Default for StitchWireCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl StitchWireCodec {
    /// Creates a new `StitchWireCodec` with standard configuration.
    pub fn new() -> Self {
        Self {
            profile: OptimizationProfile::Balanced,
            flags: WireFlags::new(false, false, false),
        }
    }

    /// Sets the default wire optimization profile.
    pub fn with_profile(mut self, profile: OptimizationProfile) -> Self {
        self.profile = profile;
        self
    }
}

/// A parsed incoming frame received from a Tokio stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WirePacket {
    pub header: WireHeader,
    pub payload: BytesMut,
}

impl Decoder for StitchWireCodec {
    type Item = WirePacket;
    type Error = TokioWireError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 2 {
            return Ok(None);
        }

        // 1. SWAR Fast-path search for WIRE_MAGIC (0x5354 / "ST")
        if let Some(magic_offset) = find_magic_swar(src) {
            if magic_offset > 0 {
                src.advance(magic_offset);
            }
        } else {
            let discard_len = src.len().saturating_sub(1);
            src.advance(discard_len);
            return Ok(None);
        }

        if src.len() < 2 {
            return Ok(None);
        }

        // 2. Attempt header parse
        let (header, header_len) = match WireHeader::parse(src) {
            Ok(res) => res,
            Err(WireError::UnexpectedEof { .. }) => return Ok(None),
            Err(WireError::InvalidMagic(_)) | Err(WireError::UnsupportedVersion(_)) => {
                src.advance(1);
                return self.decode(src);
            }
            Err(e) => return Err(e.into()),
        };

        // 3. Check full frame size
        let total_len = checked_frame_total_len(header_len, header.payload_len)?;
        if src.len() < total_len {
            src.reserve(total_len - src.len());
            return Ok(None);
        }

        // 4. Validate CRC and unpack frame
        let frame_bytes = src.split_to(total_len);
        let (_unpacked_hdr, payload_slice) = unpack_frame(&frame_bytes)?;

        let payload = BytesMut::from(payload_slice);

        Ok(Some(WirePacket { header, payload }))
    }
}

impl Encoder<&[u8]> for StitchWireCodec {
    type Error = TokioWireError;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<(), Self::Error> {
        let header = WireHeader {
            profile: self.profile,
            flags: self.flags,
            payload_len: item.len(),
            schema_hash: None,
        };

        let max_total_len = checked_frame_total_len(20, item.len())?;
        dst.reserve(max_total_len);

        let mut scratch = vec![0u8; max_total_len];
        let written = pack_frame(&header, item, &mut scratch)?;
        dst.put_slice(&scratch[..written]);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_encode_decode_roundtrip() {
        let mut codec = StitchWireCodec::new();
        let mut buf = BytesMut::new();

        let payload = b"Hello Tokio Stitch Wire Adapter!";
        codec.encode(payload.as_slice(), &mut buf).unwrap();

        let packet = codec.decode(&mut buf).unwrap().expect("Packet decoded");
        assert_eq!(&packet.payload[..], payload);
    }
}
