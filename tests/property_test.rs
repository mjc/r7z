use num_traits::FromPrimitive;
use r7z::Property;

#[test]
fn choose_property() {
    let result = Property::AdditionalStreamsInfo;
    assert_eq!(Property::from_u8(0x03).unwrap(), result);
}
