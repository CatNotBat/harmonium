#![no_main]
use harmonium_modem::framer::{Deframer, cobs_decode, cobs_encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // COBS round-trip on the raw input. `cobs_encode` appends a terminating 0x00
    // delimiter, so the frame body (everything before it) must decode back to the
    // input and contain no 0 byte itself.
    let enc = cobs_encode(data);
    let body = &enc[..enc.len().saturating_sub(1)];
    assert_eq!(cobs_decode(body), Some(data.to_vec()));
    assert!(!body.contains(&0));

    // Drive one Deframer over the rest of the input in variable-size chunks.
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let chunk_size = 1 + (first % 64) as usize;
    let mut deframer = Deframer::new();
    for chunk in rest.chunks(chunk_size) {
        if chunk.first() == Some(&0xFF) {
            deframer.lost();
        }
        let _ = deframer.push(chunk);
    }
});
