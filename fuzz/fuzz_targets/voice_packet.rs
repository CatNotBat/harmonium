#![no_main]
use harmonium_voice::VoicePacket;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = VoicePacket::from_bytes(data) {
        let reparsed = VoicePacket::from_bytes(&p.to_bytes()).expect("reparse must succeed");
        assert_eq!(reparsed, p);
    }
});
