use r7z::{CoderInfo, Folder};

mod support;

// LZMA coder bytes from test_1.7z:
// flags=0x23 (id_size=3, simple, has_props), codec_id=[03,01,01], prop_size=5, props=[5d,00,10,00,00]
const LZMA_CODER_BYTES: &[u8] = &[0x23, 0x03, 0x01, 0x01, 0x05, 0x5d, 0x00, 0x10, 0x00, 0x00];

#[test]
fn parse_lzma_coder_info() {
    let (remaining, coder) = CoderInfo::parse(LZMA_CODER_BYTES).unwrap();
    assert!(remaining.is_empty());
    assert_eq!(coder.codec_id.as_slice(), &[0x03, 0x01, 0x01]);
    assert_eq!(coder.num_in_streams, 1);
    assert_eq!(coder.num_out_streams, 1);
    assert_eq!(
        coder.properties.as_deref(),
        Some(&[0x5d_u8, 0x00, 0x10, 0x00, 0x00][..])
    );
}

#[test]
fn parse_simple_coder_no_props() {
    // flags=0x01 (id_size=1, simple, no props), codec_id=[0x00]
    let bytes = &[0x01, 0x00];
    let (remaining, coder) = CoderInfo::parse(bytes).unwrap();
    assert!(remaining.is_empty());
    assert_eq!(coder.codec_id.as_slice(), &[0x00]);
    assert_eq!(coder.num_in_streams, 1);
    assert_eq!(coder.num_out_streams, 1);
    assert_eq!(coder.properties, None);
}

#[test]
fn parse_folder_single_lzma() {
    // Folder with 1 LZMA coder: num_coders=01, then CoderInfo bytes
    let bytes: Vec<u8> = std::iter::once(0x01u8)
        .chain(LZMA_CODER_BYTES.iter().copied())
        .collect();
    let (remaining, folder) = Folder::parse(&bytes).unwrap();
    assert!(remaining.is_empty());
    assert_eq!(folder.coders.len(), 1);
    assert_eq!(folder.coders[0].codec_id.as_slice(), &[0x03, 0x01, 0x01]);
    assert_eq!(folder.bind_pairs.len(), 0);
    assert_eq!(folder.packed_indices.len(), 0); // implicit single packed index
}

#[test]
fn parse_encoded_header_coder_details() {
    let buf = support::valid_7z_string();
    let (input, sig) = r7z::SignatureHeader::parse(&buf).unwrap();
    let offset = usize::try_from(sig.next_header_offset).expect("next_header_offset fits in usize");
    let (input, _tag) = r7z::find_next_property_id(input, offset).unwrap();
    let (_input, eh) = r7z::EncodedHeader::parse(input).unwrap();

    // Validate PackInfo
    assert_eq!(eh.pack_info.num_pack_streams, 1);

    // Validate UnpackInfo
    assert_eq!(eh.unpack_info.num_folders, 1);
    let folder = eh.unpack_info.parse_folder(0).unwrap();
    assert_eq!(folder.coders.len(), 1);
    assert_eq!(folder.coders[0].codec_id.as_slice(), &[0x03, 0x01, 0x01]); // LZMA
    assert!(folder.coders[0].properties.is_some());
}
