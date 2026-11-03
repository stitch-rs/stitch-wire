//! High-throughput UDP datagram batch and scatter-gather transport adapter for `stitch-wire`.
//!
//! Enables zero-allocation UDP datagram streaming for low-latency games and telemetry feeds.

use std::net::{SocketAddr, UdpSocket};

use stitch_wire_core::error::WireError;
use stitch_wire_core::frame::{WireHeader, pack_frame, pack_frame_vectored, unpack_frame};

/// UDP Batch Sender streaming framed packets to a target endpoint.
pub struct UdpBatchSender {
    socket: UdpSocket,
    target: SocketAddr,
}

impl UdpBatchSender {
    /// Creates a new `UdpBatchSender` bound to `local_addr` sending to `target`.
    pub fn new(local_addr: SocketAddr, target: SocketAddr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(local_addr)?;
        Ok(Self { socket, target })
    }

    /// Creates a new `UdpBatchSender` from an existing `UdpSocket`.
    pub fn from_socket(socket: UdpSocket, target: SocketAddr) -> Self {
        Self { socket, target }
    }

    /// Returns a reference to the underlying socket.
    #[inline]
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Returns the target endpoint address.
    #[inline]
    pub fn target(&self) -> SocketAddr {
        self.target
    }

    /// Packs and immediately sends a framed payload over UDP using a scratchpad buffer.
    pub fn send_frame(
        &self,
        header: &WireHeader,
        payload: &[u8],
        scratch: &mut [u8],
    ) -> Result<usize, WireError> {
        let frame_len = pack_frame(header, payload, scratch)?;
        self.socket
            .send_to(&scratch[..frame_len], self.target)
            .map_err(|_| WireError::UnexpectedEof {
                required: frame_len,
                available: 0,
            })
    }

    /// Packs payload into a vectored frame and sends it directly via scatter-gather or contiguous copy.
    pub fn send_vectored(
        &self,
        header: &WireHeader,
        payload: &[u8],
        scratch: &mut [u8],
    ) -> Result<usize, WireError> {
        let vectored = pack_frame_vectored(header, payload)?;
        let total = vectored.total_len();
        if scratch.len() < total {
            return Err(WireError::UnexpectedEof {
                required: total,
                available: scratch.len(),
            });
        }
        let written = vectored.copy_to_slice(scratch)?;
        self.socket
            .send_to(&scratch[..written], self.target)
            .map_err(|_| WireError::UnexpectedEof {
                required: written,
                available: 0,
            })
    }

    /// Sends raw pre-packed frame bytes directly.
    pub fn send_raw_frame(&self, frame_bytes: &[u8]) -> Result<usize, WireError> {
        self.socket
            .send_to(frame_bytes, self.target)
            .map_err(|_| WireError::UnexpectedEof {
                required: frame_bytes.len(),
                available: 0,
            })
    }
}

/// UDP Batch Receiver receiving and decoding framed packets.
pub struct UdpBatchReceiver {
    socket: UdpSocket,
}

impl UdpBatchReceiver {
    /// Creates a new `UdpBatchReceiver` bound to the specified address.
    pub fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        Ok(Self { socket })
    }

    /// Creates a new `UdpBatchReceiver` from an existing `UdpSocket`.
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self { socket }
    }

    /// Returns a reference to the underlying socket.
    #[inline]
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Receives a datagram into `buf`, returning bytes read and the sender address.
    pub fn recv_raw(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf)
    }

    /// Receives a datagram into `buf` and decodes the frame in-place.
    pub fn recv_frame<'a>(
        &self,
        buf: &'a mut [u8],
    ) -> Result<((WireHeader, &'a [u8]), SocketAddr), WireError> {
        let (len, src) = self
            .socket
            .recv_from(buf)
            .map_err(|_| WireError::UnexpectedEof {
                required: 1,
                available: 0,
            })?;
        let (header, payload) = unpack_frame(&buf[..len])?;
        Ok(((header, payload), src))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stitch_wire_core::frame::{OptimizationProfile, WireFlags};

    #[test]
    fn test_udp_batch_sender_receiver_roundtrip() {
        let receiver =
            UdpBatchReceiver::bind("127.0.0.1:0".parse().unwrap()).expect("receiver bind");
        let recv_addr = receiver.socket().local_addr().expect("local addr");

        let sender =
            UdpBatchSender::new("127.0.0.1:0".parse().unwrap(), recv_addr).expect("sender bind");

        let header = WireHeader {
            profile: OptimizationProfile::Realtime,
            flags: WireFlags::default(),
            payload_len: 12,
            schema_hash: Some(0xDEADBEEF),
        };
        let payload = b"hello_udp_io";
        let mut scratch = [0u8; 512];

        let sent = sender
            .send_frame(&header, payload, &mut scratch)
            .expect("send frame");
        assert!(sent > 0);

        let mut recv_buf = [0u8; 512];
        let ((hdr, body), src) = receiver.recv_frame(&mut recv_buf).expect("recv frame");
        assert_eq!(body, payload);
        assert_eq!(hdr.schema_hash, Some(0xDEADBEEF));
        assert_eq!(src, sender.socket().local_addr().unwrap());
    }

    #[test]
    fn test_udp_batch_sender_vectored_roundtrip() {
        let receiver =
            UdpBatchReceiver::bind("127.0.0.1:0".parse().unwrap()).expect("receiver bind");
        let recv_addr = receiver.socket().local_addr().expect("local addr");

        let sender =
            UdpBatchSender::new("127.0.0.1:0".parse().unwrap(), recv_addr).expect("sender bind");

        let header = WireHeader {
            profile: OptimizationProfile::Balanced,
            flags: WireFlags::default(),
            payload_len: 16,
            schema_hash: Some(0xCAFEBABE),
        };
        let payload = b"vectored_payload";
        let mut scratch = [0u8; 512];

        let sent = sender
            .send_vectored(&header, payload, &mut scratch)
            .expect("send vectored");
        assert!(sent > 0);

        let mut recv_buf = [0u8; 512];
        let ((hdr, body), _src) = receiver.recv_frame(&mut recv_buf).expect("recv frame");
        assert_eq!(body, payload);
        assert_eq!(hdr.schema_hash, Some(0xCAFEBABE));
    }
}
