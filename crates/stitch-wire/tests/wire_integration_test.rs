use stitch_data::prelude::*;
use stitch_wire::prelude::*;

#[derive(Debug, PartialEq, Record)]
struct Packet {
    id: u32,
    #[stitch(zigzag)]
    delta: i32,
}

#[test]
fn test_wire_record_packing_and_unpacking() {
    let packet = Packet { id: 42, delta: -15 };

    let mut scratch = [0u8; 64];
    let mut frame_buf = [0u8; 128];

    let written = pack_record(
        &packet,
        stitch_wire::OptimizationProfile::Balanced,
        &mut scratch,
        &mut frame_buf,
    )
    .unwrap();
    assert!(written >= 8);

    let unpacked: Packet = unpack_record(&frame_buf[..written]).unwrap();
    assert_eq!(packet, unpacked);
}
