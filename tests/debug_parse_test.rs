mod support;

#[test]
fn debug_full_header_parse() {
    let data = std::fs::read("tests/fixtures/test_1.7z").unwrap();

    let (input, signature) = r7z::SignatureHeader::parse(&data).unwrap();
    let offset = signature.next_header_offset as usize;
    let (input, _prop) = r7z::find_next_property_id(input, offset).unwrap();
    let (_, encoded_header) = r7z::EncodedHeader::parse(input).unwrap();

    let pi = &encoded_header.pack_info;
    let ui = &encoded_header.unpack_info;
    let data_start = 32 + pi.pack_pos as usize;
    let data_end = data_start + pi.pack_size[0] as usize;
    let packed = &data[data_start..data_end];
    let folder = &ui.folders[0];
    let unpack_size = ui.unpack_sizes[0];

    println!("pack_pos: {}", pi.pack_pos);
    println!("pack_size: {}", pi.pack_size[0]);
    println!("unpack_size: {}", unpack_size);

    let decompressed = r7z::decompress_folder(folder, packed, unpack_size).unwrap();
    println!("decompressed len: {}", decompressed.len());
    println!("first 40 bytes: {:02x?}", &decompressed[..40.min(decompressed.len())]);

    let result = r7z::Header::parse(&decompressed);
    match &result {
        Ok((remaining, hdr)) => {
            println!("Header parse OK, remaining: {} bytes", remaining.len());
            println!("has main_streams: {}", hdr.main_streams_info.is_some());
            println!("has files_info: {}", hdr.files_info.is_some());
            if let Some(fi) = &hdr.files_info {
                println!("num_files: {}", fi.num_files);
                for name in &fi.names {
                    println!("  file: {}", name);
                }
            }
        }
        Err(e) => {
            println!("Header parse FAILED: {:?}", e);
        }
    }
}
