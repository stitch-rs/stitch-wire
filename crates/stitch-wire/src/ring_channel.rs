//! Lock-free SPSC zero-copy streaming channel backed by `wire-ring`.
//!
//! Provides zero-copy frame packing and streaming parsing directly into and out of
//! virtual memory mirrored ring buffers without intermediate scratchpad copying.

use stitch_wire_core::error::WireError;
use stitch_wire_core::frame::{
    FrameReader, VectoredFrame, WireHeader, checked_frame_total_len, pack_frame,
};
use wire_ring::builder::RingError;
use wire_ring::channel::{Consumer, Producer};
use wire_ring::presets::Ring;
use wire_ring::storage::{HeapStorage, MirroredStorage, StorageBackend};

/// Outbound zero-copy wire frame sink backed by a `wire-ring` Producer.
pub struct WireRingSink<S: StorageBackend = MirroredStorage> {
    producer: Producer<S>,
}

impl<S: StorageBackend> WireRingSink<S> {
    /// Wraps an existing `wire-ring` producer.
    pub const fn new(producer: Producer<S>) -> Self {
        Self { producer }
    }

    /// Returns the total usable capacity of the underlying ring buffer.
    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.producer.capacity()
    }

    /// Returns the number of writable bytes currently available.
    #[inline(always)]
    pub fn available_write(&mut self) -> usize {
        self.producer.available_write()
    }

    /// Returns a mutable reference to the underlying `Producer`.
    #[inline(always)]
    pub fn producer_mut(&mut self) -> &mut Producer<S> {
        &mut self.producer
    }

    /// Consumes the sink and returns the inner `Producer`.
    pub fn into_inner(self) -> Producer<S> {
        self.producer
    }

    /// Packs and writes a wire frame directly into leased ring memory.
    ///
    /// # Zero-Copy Guarantee
    /// The frame header, payload, and Castagnoli CRC32 are written directly into
    /// the ring buffer's contiguous virtual memory grant without an intermediate buffer.
    pub fn send_frame(&mut self, header: &WireHeader, payload: &[u8]) -> Result<usize, WireError> {
        let has_schema = header.schema_hash.is_some();
        let varint_len = stitch_wire_core::varint::prefix_varint_len(payload.len() as u64);
        let schema_len = if has_schema { 8 } else { 0 };
        let header_len = 3 + varint_len + schema_len;
        let total_len = checked_frame_total_len(header_len, payload.len())?;

        let mut grant = self
            .producer
            .grant(total_len)
            .ok_or(WireError::UnexpectedEof {
                required: total_len,
                available: 0,
            })?;

        if grant.len() < total_len {
            return Err(WireError::UnexpectedEof {
                required: total_len,
                available: grant.len(),
            });
        }

        let written = pack_frame(header, payload, &mut grant[..total_len])?;
        grant.commit(written);
        Ok(written)
    }

    /// Writes a pre-assembled scatter-gather vectored frame directly into leased ring memory.
    pub fn send_vectored(&mut self, frame: &VectoredFrame<'_>) -> Result<usize, WireError> {
        let total_len = frame.total_len();

        let mut grant = self
            .producer
            .grant(total_len)
            .ok_or(WireError::UnexpectedEof {
                required: total_len,
                available: 0,
            })?;

        if grant.len() < total_len {
            return Err(WireError::UnexpectedEof {
                required: total_len,
                available: grant.len(),
            });
        }

        let written = frame.copy_to_slice(&mut grant[..total_len])?;
        grant.commit(written);
        Ok(written)
    }

    /// Writes raw bytes into the ring buffer.
    #[inline]
    pub fn send_slice(&mut self, data: &[u8]) -> usize {
        self.producer.write_slice(data)
    }
}

/// Inbound zero-copy wire frame stream backed by a `wire-ring` Consumer.
pub struct WireRingStream<S: StorageBackend = MirroredStorage> {
    consumer: Consumer<S>,
}

impl<S: StorageBackend> WireRingStream<S> {
    /// Wraps an existing `wire-ring` consumer.
    pub const fn new(consumer: Consumer<S>) -> Self {
        Self { consumer }
    }

    /// Returns the total usable capacity of the underlying ring buffer.
    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.consumer.capacity()
    }

    /// Returns the number of readable bytes currently available.
    #[inline(always)]
    pub fn available_read(&mut self) -> usize {
        self.consumer.available_read()
    }

    /// Returns a mutable reference to the underlying `Consumer`.
    #[inline(always)]
    pub fn consumer_mut(&mut self) -> &mut Consumer<S> {
        &mut self.consumer
    }

    /// Consumes the stream and returns the inner `Consumer`.
    pub fn into_inner(self) -> Consumer<S> {
        self.consumer
    }

    /// Polls for the next complete frame in the ring, invoking `f` with the header and payload.
    ///
    /// If a frame is successfully processed, its consumed bytes are automatically committed.
    /// If only a partial frame or no bytes are available, returns `Ok(None)` without committing.
    pub fn poll_frame<F, R>(&mut self, f: F) -> Result<Option<R>, WireError>
    where
        F: FnOnce(&WireHeader, &[u8]) -> R,
    {
        let Some(grant) = self.consumer.grant() else {
            return Ok(None);
        };

        if grant.is_empty() {
            return Ok(None);
        }

        let (committed_len, user_result) = {
            let slice: &[u8] = &grant;
            let mut reader = FrameReader::new(slice);
            match reader.next_frame() {
                Ok(Some(frame_view)) => {
                    let frame_len = frame_view.frame_len;
                    let res = f(&frame_view.header, frame_view.payload);
                    (frame_len, Some(res))
                }
                Ok(None) | Err(WireError::UnexpectedEof { .. }) => (0, None),
                Err(err) => return Err(err),
            }
        };

        if committed_len > 0 {
            grant.commit(committed_len);
        }

        Ok(user_result)
    }

    /// Drains all currently available complete frames from the ring buffer.
    ///
    /// Returns the number of frames successfully processed and committed.
    pub fn poll_drain<F>(&mut self, mut f: F) -> Result<usize, WireError>
    where
        F: FnMut(&WireHeader, &[u8]),
    {
        let Some(grant) = self.consumer.grant() else {
            return Ok(0);
        };

        if grant.is_empty() {
            return Ok(0);
        }

        let (total_consumed, count, err) = {
            let slice: &[u8] = &grant;
            let mut reader = FrameReader::new(slice);
            let mut count = 0;
            let mut total_consumed = 0;
            let mut err = None;

            loop {
                match reader.next_frame() {
                    Ok(Some(frame_view)) => {
                        f(&frame_view.header, frame_view.payload);
                        total_consumed += frame_view.frame_len;
                        count += 1;
                    }
                    Ok(None) | Err(WireError::UnexpectedEof { .. }) => {
                        break;
                    }
                    Err(e) => {
                        err = Some(e);
                        break;
                    }
                }
            }
            (total_consumed, count, err)
        };

        if total_consumed > 0 {
            grant.commit(total_consumed);
        }

        if let Some(e) = err {
            return Err(e);
        }

        Ok(count)
    }

    /// Reads raw bytes from the ring buffer into `dst`.
    #[inline]
    pub fn read_slice(&mut self, dst: &mut [u8]) -> usize {
        self.consumer.read_slice(dst)
    }
}

/// Creates a new MMU-mirrored SPSC wire ring channel.
///
/// Allocates virtual memory mirrored storage of `capacity` bytes (must be a power of two
/// and multiple of allocation granularity, e.g. 64 KiB).
pub fn wire_ring_channel(
    capacity: usize,
) -> Result<
    (
        WireRingSink<MirroredStorage>,
        WireRingStream<MirroredStorage>,
    ),
    RingError,
> {
    let (tx, rx) = Ring::network_default(capacity)?;
    Ok((WireRingSink::new(tx), WireRingStream::new(rx)))
}

/// Creates a new heap-allocated SPSC wire ring channel.
pub fn wire_ring_heap_channel(
    capacity: usize,
) -> Result<(WireRingSink<HeapStorage>, WireRingStream<HeapStorage>), RingError> {
    let (tx, rx) = Ring::heap(capacity)?;
    Ok((WireRingSink::new(tx), WireRingStream::new(rx)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stitch_wire_core::frame::{OptimizationProfile, WireFlags};

    #[test]
    fn test_wire_ring_heap_channel_roundtrip() {
        let (mut sink, mut stream) = wire_ring_heap_channel(4096).expect("heap ring channel");

        let header = WireHeader {
            profile: OptimizationProfile::Direct,
            flags: WireFlags::default(),
            payload_len: 12,
            schema_hash: None,
        };
        let payload = b"hello_stitch";

        let written = sink.send_frame(&header, payload).expect("send frame");
        assert!(written > 0);

        let mut received = false;
        let processed = stream
            .poll_frame(|hdr, data| {
                assert_eq!(hdr.payload_len, 12);
                assert_eq!(data, b"hello_stitch");
                received = true;
            })
            .expect("poll frame");

        assert!(processed.is_some());
        assert!(received);

        // Verify ring is now empty
        assert_eq!(stream.available_read(), 0);
    }

    #[test]
    fn test_wire_ring_mirrored_channel_continuous_drain() {
        let (mut sink, mut stream) = wire_ring_channel(64 * 1024).expect("mirrored ring channel");

        let frame_count = 100;
        for i in 0..frame_count {
            let payload = format!("payload_packet_{i}");
            let header = WireHeader {
                profile: OptimizationProfile::Realtime,
                flags: WireFlags::default(),
                payload_len: payload.len(),
                schema_hash: None,
            };
            sink.send_frame(&header, payload.as_bytes())
                .expect("send frame");
        }

        let mut drained = 0;
        let count = stream
            .poll_drain(|_hdr, _data| {
                drained += 1;
            })
            .expect("drain frames");

        assert_eq!(count, frame_count);
        assert_eq!(drained, frame_count);
        assert_eq!(stream.available_read(), 0);
    }
}
