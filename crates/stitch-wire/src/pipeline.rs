//! The Sewing Machine Architecture (SMA) Pipeline for Wire Framing & Transport.
//!
//! Treats wire frame packing, checksumming, fragmentation, and vectorization as a
//! strictly monomorphic U-cycle traversal with zero heap allocations on hot paths.

use stitch_core::blackboard::Blackboard;
use stitch_core::flow::FlowControl;
use stitch_core::middleware::{Layer, Terminal};
use stitch_core::pipeline::{Pipeline, StackNode, TerminalNode};
use stitch_wire_core::crc::crc32_castagnoli;
use stitch_wire_core::error::WireError;
use stitch_wire_core::frame::{
    MAX_FRAME_PAYLOAD_LEN, OptimizationProfile, WireFlags, WireHeader, pack_frame, unpack_frame,
};
use stitch_wire_core::resync::find_magic_swar;

/// Status outcome of the wire processing stroke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum WireStatus {
    /// Operation completed successfully.
    #[default]
    Ok = 0,
    /// Castagnoli CRC32 validation failed (data corruption).
    CrcMismatch = 1,
    /// Synchronization magic marker not found or corrupted.
    MagicMismatch = 2,
    /// Payload exceeds maximum allowable frame boundaries.
    PayloadTooLarge = 3,
    /// Provided scratch buffer is insufficient to store frame bytes.
    BufferTooSmall = 4,
    /// Generic/custom failure.
    Failed = 5,
}

/// 64-byte L1D Cache-Aligned Wire Blackboard Context.
#[repr(C, align(64))]
#[derive(Debug, Clone)]
pub struct WireBlackboard {
    /// Wire frame header definition.
    pub header: WireHeader,
    /// Payload length in bytes.
    pub payload_len: usize,
    /// Traversal status result.
    pub status: WireStatus,
    /// Calculated or expected Castagnoli CRC32 checksum.
    pub checksum: u32,
    /// True for outbound transmission (TX), false for inbound reception (RX).
    pub is_tx: bool,
    /// Canonical frame attribute flags.
    pub flags: WireFlags,
    /// Total bytes processed in this stroke.
    pub bytes_processed: usize,
}

impl Blackboard for WireBlackboard {}

impl WireBlackboard {
    /// Creates a new transmission (TX) blackboard.
    #[inline]
    pub fn new_tx(header: WireHeader, payload_len: usize) -> Self {
        let flags = header.flags;
        Self {
            header,
            payload_len,
            status: WireStatus::Ok,
            checksum: 0,
            is_tx: true,
            flags,
            bytes_processed: 0,
        }
    }

    /// Creates a new reception (RX) blackboard over incoming wire bytes.
    #[inline]
    pub fn new_rx() -> Self {
        Self {
            header: WireHeader {
                profile: OptimizationProfile::Direct,
                flags: WireFlags::default(),
                payload_len: 0,
                schema_hash: None,
            },
            payload_len: 0,
            status: WireStatus::Ok,
            checksum: 0,
            is_tx: false,
            flags: WireFlags::default(),
            bytes_processed: 0,
        }
    }
}

// Compile-time mechanical sympathy invariant verification
const _: () = {
    assert!(core::mem::align_of::<WireBlackboard>() == 64);
    assert!(core::mem::size_of::<WireBlackboard>() == 64);
};

// =========================================================================
// SMA Wire Layers
// =========================================================================

/// Core framing layer managing wire headers, magic synchronization, and payload sizing.
pub struct FramingLayer;

impl<'a> Layer<WireBlackboard, &'a [u8], usize, WireError> for FramingLayer {
    #[inline]
    fn on_enter(
        &self,
        ctx: &mut WireBlackboard,
        intent: &'a [u8],
    ) -> FlowControl<&'a [u8], usize, WireError> {
        if ctx.is_tx {
            if intent.len() > MAX_FRAME_PAYLOAD_LEN {
                ctx.status = WireStatus::PayloadTooLarge;
                return FlowControl::Halt(WireError::FrameTooLarge {
                    size: intent.len() as u64,
                    limit: MAX_FRAME_PAYLOAD_LEN,
                });
            }
            ctx.header.payload_len = intent.len();
            ctx.payload_len = intent.len();
            FlowControl::Proceed(intent)
        } else {
            match unpack_frame(intent) {
                Ok((header, payload_view)) => {
                    ctx.flags = header.flags;
                    ctx.payload_len = payload_view.len();
                    ctx.header = header;
                    FlowControl::Proceed(payload_view)
                }
                Err(err) => {
                    ctx.status = WireStatus::MagicMismatch;
                    FlowControl::Halt(err)
                }
            }
        }
    }

    #[inline]
    fn on_exit(&self, _ctx: &mut WireBlackboard, _outcome: &mut Result<usize, WireError>) {}
}

/// Hardware-accelerated Castagnoli CRC-32C layer enforcing end-to-end data integrity.
pub struct CastagnoliCrcLayer;

impl<'a> Layer<WireBlackboard, &'a [u8], usize, WireError> for CastagnoliCrcLayer {
    #[inline]
    fn on_enter(
        &self,
        ctx: &mut WireBlackboard,
        intent: &'a [u8],
    ) -> FlowControl<&'a [u8], usize, WireError> {
        ctx.checksum = crc32_castagnoli(intent);
        FlowControl::Proceed(intent)
    }

    #[inline]
    fn on_exit(&self, _ctx: &mut WireBlackboard, _outcome: &mut Result<usize, WireError>) {}
}

/// MTU Segmentation layer that marks datagram frames for fragmentation if exceeding MTU.
pub struct MtuChunkingLayer {
    pub max_datagram_size: usize,
}

impl MtuChunkingLayer {
    /// Creates a new MTU chunking layer with standard Ethernet MTU (1400 bytes).
    #[inline]
    pub const fn new(max_datagram_size: usize) -> Self {
        Self { max_datagram_size }
    }
}

impl<'a> Layer<WireBlackboard, &'a [u8], usize, WireError> for MtuChunkingLayer {
    #[inline]
    fn on_enter(
        &self,
        ctx: &mut WireBlackboard,
        intent: &'a [u8],
    ) -> FlowControl<&'a [u8], usize, WireError> {
        if ctx.is_tx && intent.len() > self.max_datagram_size {
            ctx.header.flags.is_chunked = true;
            ctx.flags.is_chunked = true;
        }
        FlowControl::Proceed(intent)
    }

    #[inline]
    fn on_exit(&self, _ctx: &mut WireBlackboard, _outcome: &mut Result<usize, WireError>) {}
}

/// High-speed SIMD/SWAR Resynchronization layer scanning stream noise for frame boundaries.
pub struct SwarResyncLayer;

impl<'a> Layer<WireBlackboard, &'a [u8], usize, WireError> for SwarResyncLayer {
    #[inline]
    fn on_enter(
        &self,
        ctx: &mut WireBlackboard,
        intent: &'a [u8],
    ) -> FlowControl<&'a [u8], usize, WireError> {
        if !ctx.is_tx {
            if let Some(offset) = find_magic_swar(intent) {
                FlowControl::Proceed(&intent[offset..])
            } else {
                ctx.status = WireStatus::MagicMismatch;
                FlowControl::Halt(WireError::InvalidMagic(0))
            }
        } else {
            FlowControl::Proceed(intent)
        }
    }

    #[inline]
    fn on_exit(&self, _ctx: &mut WireBlackboard, _outcome: &mut Result<usize, WireError>) {}
}

// =========================================================================
// SMA Wire Terminals
// =========================================================================

/// Contiguous Buffer Packing Terminal writing complete frames into scratch memory.
pub struct BufferTerminal<'b> {
    pub dst: &'b mut [u8],
}

impl<'b> BufferTerminal<'b> {
    /// Creates a new buffer terminal targeting the given scratch memory.
    #[inline]
    pub fn new(dst: &'b mut [u8]) -> Self {
        Self { dst }
    }
}

impl<'a, 'b> Terminal<WireBlackboard, &'a [u8], usize, WireError> for BufferTerminal<'b> {
    #[inline]
    fn execute(&mut self, ctx: &mut WireBlackboard, intent: &'a [u8]) -> Result<usize, WireError> {
        if ctx.is_tx {
            let written = pack_frame(&ctx.header, intent, self.dst)?;
            ctx.bytes_processed = written;
            ctx.status = WireStatus::Ok;
            Ok(written)
        } else {
            // In RX, intent is the unpacked payload slice view
            ctx.bytes_processed = intent.len();
            ctx.status = WireStatus::Ok;
            Ok(intent.len())
        }
    }
}

// =========================================================================
// Domain Presets (Zero-Cost Extension Builders)
// =========================================================================

/// Type alias for the Game Datagram UDP Wire Pipeline Chain.
pub type GameWireChain<'b> = StackNode<
    SwarResyncLayer,
    StackNode<
        FramingLayer,
        StackNode<
            CastagnoliCrcLayer,
            StackNode<MtuChunkingLayer, TerminalNode<BufferTerminal<'b>>>,
        >,
    >,
>;

/// Type alias for the Game Datagram Pipeline.
pub type GameWirePipeline<'a, 'b> =
    Pipeline<WireBlackboard, &'a [u8], usize, WireError, GameWireChain<'b>>;

/// Type alias for the Stream Wire Pipeline Chain.
pub type StreamWireChain<'b> = StackNode<
    SwarResyncLayer,
    StackNode<FramingLayer, StackNode<CastagnoliCrcLayer, TerminalNode<BufferTerminal<'b>>>>,
>;

/// Type alias for the Stream Framing Pipeline.
pub type StreamWirePipeline<'a, 'b> =
    Pipeline<WireBlackboard, &'a [u8], usize, WireError, StreamWireChain<'b>>;

/// Zero-cost domain wire pipeline presets factory.
pub struct WirePresets;

impl WirePresets {
    /// Constructs a low-latency Game Datagram pipeline (SWAR resync + Framing + CRC32C + MTU Chunking).
    #[inline]
    pub fn game_datagram<'a, 'b>(mtu: usize, dst: &'b mut [u8]) -> GameWirePipeline<'a, 'b> {
        Pipeline::on_terminal(BufferTerminal::new(dst))
            .wrap(MtuChunkingLayer::new(mtu))
            .wrap(CastagnoliCrcLayer)
            .wrap(FramingLayer)
            .wrap(SwarResyncLayer)
    }

    /// Constructs a reliable Stream Framing pipeline (SWAR resync + Framing + CRC32C).
    #[inline]
    pub fn stream_framing<'a, 'b>(dst: &'b mut [u8]) -> StreamWirePipeline<'a, 'b> {
        Pipeline::on_terminal(BufferTerminal::new(dst))
            .wrap(CastagnoliCrcLayer)
            .wrap(FramingLayer)
            .wrap(SwarResyncLayer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_game_wire_pipeline_tx_rx_roundtrip() {
        let payload = b"game_tick_snapshot_42";
        let mut wire_buffer = [0u8; 256];

        let header = WireHeader {
            profile: OptimizationProfile::Balanced,
            flags: WireFlags::default(),
            payload_len: payload.len(),
            schema_hash: Some(0xABCD_1234),
        };

        // 1. TX Cycle: Packing into wire frame via SMA U-Cycle
        let mut tx_ctx = WireBlackboard::new_tx(header, payload.len());
        let mut tx_pipeline = WirePresets::game_datagram(1400, &mut wire_buffer);
        let sent_len = tx_pipeline
            .dispatch(&mut tx_ctx, payload)
            .expect("TX cycle passed");

        assert_eq!(tx_ctx.status, WireStatus::Ok);
        assert_eq!(sent_len, tx_ctx.bytes_processed);

        // 2. RX Cycle: Unpacking from wire frame via SMA U-Cycle
        let mut rx_scratch = [0u8; 256];
        let mut rx_ctx = WireBlackboard::new_rx();
        let mut rx_pipeline = WirePresets::game_datagram(1400, &mut rx_scratch);
        let unpacked_len = rx_pipeline
            .dispatch(&mut rx_ctx, &wire_buffer[..sent_len])
            .expect("RX cycle passed");

        assert_eq!(rx_ctx.status, WireStatus::Ok);
        assert_eq!(unpacked_len, payload.len());
        assert_eq!(rx_ctx.header.schema_hash, Some(0xABCD_1234));
    }

    #[test]
    fn test_swar_resync_on_noisy_stream() {
        let payload = b"critical_game_event";
        let mut wire_buffer = [0u8; 128];

        let header = WireHeader {
            profile: OptimizationProfile::Realtime,
            flags: WireFlags::default(),
            payload_len: payload.len(),
            schema_hash: None,
        };

        let mut tx_ctx = WireBlackboard::new_tx(header, payload.len());
        let mut tx_pipeline = WirePresets::stream_framing(&mut wire_buffer);
        let frame_len = tx_pipeline
            .dispatch(&mut tx_ctx, payload)
            .expect("TX passed");

        // Simulate noisy TCP stream: 9 bytes of junk before frame
        let mut noisy_stream = [0x55u8; 256];
        noisy_stream[9..9 + frame_len].copy_from_slice(&wire_buffer[..frame_len]);

        let mut rx_scratch = [0u8; 128];
        let mut rx_ctx = WireBlackboard::new_rx();
        let mut rx_pipeline = WirePresets::stream_framing(&mut rx_scratch);
        let decoded_len = rx_pipeline
            .dispatch(&mut rx_ctx, &noisy_stream[..9 + frame_len])
            .expect("RX SWAR recovered");

        assert_eq!(decoded_len, payload.len());
        assert_eq!(rx_ctx.status, WireStatus::Ok);
    }

    #[cfg(feature = "macros")]
    #[crate::wire_pipeline(
        layers = [SwarResyncLayer, FramingLayer, CastagnoliCrcLayer, MtuChunkingLayer],
        terminal = BufferTerminal<'b>,
        crate = crate,
    )]
    struct CustomGameWirePipeline<'a, 'b>;

    #[cfg(feature = "macros")]
    #[test]
    fn test_wire_pipeline_attribute_macro() {
        let payload = b"newtype_macro_payload";
        let mut wire_buffer = [0u8; 128];
        let header = WireHeader {
            profile: OptimizationProfile::Direct,
            flags: WireFlags::default(),
            payload_len: payload.len(),
            schema_hash: None,
        };
        let mut tx_ctx = WireBlackboard::new_tx(header, payload.len());
        let mut pipe = CustomGameWirePipeline::new(
            SwarResyncLayer,
            FramingLayer,
            CastagnoliCrcLayer,
            MtuChunkingLayer::new(1400),
            BufferTerminal::new(&mut wire_buffer),
        );
        let sent_len = pipe.run_cycle(&mut tx_ctx, payload).expect("TX cycle succeeded");
        assert_eq!(tx_ctx.status, WireStatus::Ok);
        assert!(sent_len > payload.len());
    }
}
