//! Zero-allocation UDP Batch and Vectored Streamer for `stitch-wire` frames.
//!
//! Enables high-throughput, non-allocating datagram frame transport using both
//! contiguous scratchpads and scatter-gather vectored frames (`IoSlice`).

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

    /// Packs payload into a [`VectoredFrame`] with zero heap allocations and sends it
    /// directly using contiguous copy into `scratch` or vectored fallback.
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

    /// Receives a datagram into `rx_buf` and unpacks the `stitch-wire` frame.
    ///
    /// Returns `(WireHeader, payload_slice, sender_addr)`.
    pub fn recv_frame<'a>(
        &self,
        rx_buf: &'a mut [u8],
    ) -> Result<(WireHeader, &'a [u8], SocketAddr), WireError> {
        let (bytes_read, peer) =
            self.socket
                .recv_from(rx_buf)
                .map_err(|_| WireError::UnexpectedEof {
                    required: 1,
                    available: 0,
                })?;

        let (header, payload) = unpack_frame(&rx_buf[..bytes_read])?;
        Ok((header, payload, peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stitch_wire_core::frame::{OptimizationProfile, WireFlags};

    #[test]
    fn test_udp_batch_streamer_loopback() {
        let recv_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let receiver = UdpBatchReceiver::bind(recv_addr).unwrap();
        let actual_recv_addr = receiver.socket.local_addr().unwrap();

        let sender_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let sender = UdpBatchSender::new(sender_addr, actual_recv_addr).unwrap();

        let header = WireHeader {
            profile: OptimizationProfile::Direct,
            flags: WireFlags::new(false, false, false),
            payload_len: 12,
            schema_hash: None,
        };
        let payload = b"stitch-wire!";
        let mut scratch = [0u8; 128];

        let sent = sender.send_frame(&header, payload, &mut scratch).unwrap();
        assert!(sent > payload.len());

        let mut rx_buf = [0u8; 256];
        let (rx_header, rx_payload, _peer) = receiver.recv_frame(&mut rx_buf).unwrap();

        assert_eq!(rx_header.payload_len, 12);
        assert_eq!(rx_payload, payload);

        // Test vectored dispatch
        let sent_vectored = sender
            .send_vectored(&header, payload, &mut scratch)
            .unwrap();
        assert_eq!(sent_vectored, sent);

        let (rx_v_header, rx_v_payload, _peer) = receiver.recv_frame(&mut rx_buf).unwrap();
        assert_eq!(rx_v_header.payload_len, 12);
        assert_eq!(rx_v_payload, payload);
    }
}
