//! Synchronous standard library stream adapters for the Stitch Wire protocol.
//!
//! Provides [`SyncFrameReader`] and [`SyncFrameWriter`] wrapping any [`std::io::Read`]
//! and [`std::io::Write`] streams.

use std::io::{self, Read, Write};
use stitch_wire_core::error::WireError;
use stitch_wire_core::frame::{WireHeader, checked_frame_total_len, pack_frame, unpack_frame};

/// Synchronous streaming frame reader wrapping an [`io::Read`] source.
pub struct SyncFrameReader<R> {
    reader: R,
    buffer: Vec<u8>,
}

impl<R: Read> SyncFrameReader<R> {
    /// Creates a new `SyncFrameReader` with a default 64 KB internal buffer.
    pub fn new(reader: R) -> Self {
        Self::with_capacity(reader, 64 * 1024)
    }

    /// Creates a new `SyncFrameReader` with the specified buffer capacity.
    pub fn with_capacity(reader: R, capacity: usize) -> Self {
        Self {
            reader,
            buffer: Vec::with_capacity(capacity),
        }
    }

    /// Reads and unpacks the next complete frame from the underlying reader.
    pub fn read_frame(&mut self) -> Result<Option<(WireHeader, Vec<u8>)>, WireError> {
        let mut temp_buf = [0u8; 4096];

        loop {
            // Attempt parse from accumulated buffer
            if self.buffer.len() >= 2
                && let Ok((header, header_len)) = WireHeader::parse(&self.buffer)
            {
                let total_len = checked_frame_total_len(header_len, header.payload_len)?;
                if self.buffer.len() >= total_len {
                    let (_hdr, payload) = unpack_frame(&self.buffer[..total_len])?;
                    let payload_vec = payload.to_vec();
                    self.buffer.drain(..total_len);
                    return Ok(Some((header, payload_vec)));
                }
            }

            // Read more data
            match self.reader.read(&mut temp_buf) {
                Ok(0) => {
                    if self.buffer.is_empty() {
                        return Ok(None);
                    } else {
                        return Err(WireError::UnexpectedEof {
                            required: 1,
                            available: 0,
                        });
                    }
                }
                Ok(n) => {
                    self.buffer.extend_from_slice(&temp_buf[..n]);
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_e) => return Err(WireError::PayloadDecodeError),
            }
        }
    }
}

/// Synchronous streaming frame writer wrapping an [`io::Write`] sink.
pub struct SyncFrameWriter<W> {
    writer: W,
    scratch: Vec<u8>,
}

impl<W: Write> SyncFrameWriter<W> {
    /// Creates a new `SyncFrameWriter`.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            scratch: vec![0u8; 64 * 1024],
        }
    }

    /// Packs and writes a frame directly to the underlying writer.
    pub fn write_frame(&mut self, header: &WireHeader, payload: &[u8]) -> Result<usize, WireError> {
        let max_len = checked_frame_total_len(20, payload.len())?;
        if self.scratch.len() < max_len {
            self.scratch.resize(max_len, 0);
        }

        let written = pack_frame(header, payload, &mut self.scratch)?;
        self.writer
            .write_all(&self.scratch[..written])
            .map_err(|_| WireError::PayloadDecodeError)?;
        self.writer
            .flush()
            .map_err(|_| WireError::PayloadDecodeError)?;

        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stitch_wire_core::frame::{OptimizationProfile, WireFlags};

    #[test]
    fn test_sync_stream_roundtrip() {
        let mut pipe = Vec::new();
        let mut writer = SyncFrameWriter::new(&mut pipe);

        let header = WireHeader {
            profile: OptimizationProfile::Balanced,
            flags: WireFlags::new(false, false, false),
            payload_len: 11,
            schema_hash: None,
        };

        writer.write_frame(&header, b"Hello Sync!").unwrap();

        let mut reader = SyncFrameReader::new(&pipe[..]);
        let (_unpacked_hdr, payload) = reader.read_frame().unwrap().expect("Frame read");
        assert_eq!(payload, b"Hello Sync!");
    }
}
