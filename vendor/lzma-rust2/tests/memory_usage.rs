#![cfg(feature = "encoder")]

use lzma_rust2::LzmaOptions;

#[test]
fn level_five_memory_estimate_uses_kibibytes() {
    let mut options = LzmaOptions::with_preset(5);
    options.dict_size = 16 << 20;
    assert_eq!(options.get_memory_usage(), 189_361);
}
