//! End-to-end Tokio TCP stream framing example using `StitchWireCodec`.
//!
//! Spawns an in-process TCP server and client exchanging framed packets
//! with hardware Castagnoli CRC32 validation and zero payload copying.

use futures_util::{SinkExt, StreamExt};
use stitch_wire_adapter_tokio::StitchWireCodec;
use stitch_wire_core::frame::{OptimizationProfile, WireFlags};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Tokio TCP Streaming Framing Reference Example ===");

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    println!("Server listening on: {local_addr}");

    // 1. Spawn server task
    let server_handle = tokio::spawn(async move {
        let (socket, peer_addr) = listener.accept().await.expect("Accept connection");
        println!("[Server] Connected from: {peer_addr}");

        let mut framed = Framed::new(socket, StitchWireCodec::new());

        let mut received_count = 0;
        while let Some(packet_res) = framed.next().await {
            let packet = packet_res.expect("Packet decode");
            received_count += 1;
            println!(
                "[Server] Frame #{} received: payload_len={} bytes, data={:?}",
                received_count,
                packet.header.payload_len,
                std::str::from_utf8(&packet.payload).unwrap_or("<binary>")
            );

            // Echo response back
            let echo_msg = format!("ACK:{}", received_count);
            framed
                .send(echo_msg.as_bytes())
                .await
                .expect("Send echo response");

            if received_count >= 3 {
                break;
            }
        }
    });

    // 2. Client connects and sends frames
    let client_socket = TcpStream::connect(local_addr).await?;
    println!("[Client] Connected to server at {local_addr}");

    let mut client_codec = StitchWireCodec::new().with_profile(OptimizationProfile::Balanced);
    client_codec.flags = WireFlags::new(true, false, false);

    let mut client_framed = Framed::new(client_socket, client_codec);

    for i in 1..=3 {
        let msg = format!("Telemetry payload batch #{}", i);
        println!("[Client] Sending frame #{i}...");
        client_framed.send(msg.as_bytes()).await?;

        let response = client_framed.next().await.expect("Response expected")?;
        println!(
            "[Client] Received response: {:?}",
            std::str::from_utf8(&response.payload).unwrap_or("<binary>")
        );
    }

    server_handle.await?;
    println!("=== Tokio TCP Framing Stream Completed Successfully ===");
    Ok(())
}
