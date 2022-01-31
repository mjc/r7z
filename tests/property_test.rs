use r7z::Property;

mod support;

#[test]
fn choose_property() {
    let result = Property::AdditionalStreamsInfo;
    assert_eq!(Property::from_u8(0x03).unwrap(), result);
}

#[test]
fn parse_property_id_from_offset() {
    let buf = support::valid_7z_string();
    let (input, header) = r7z::SignatureHeader::parse(&buf).unwrap();
    let (_input, property_id) =
        r7z::find_next_property_id(&input, header.next_header_offset).unwrap();
    assert_eq!(property_id, Property::EncodedHeader);
}
