use nom::{
    error::{Error, ErrorKind},
    number::streaming::le_u8,
    IResult,
};
use num::FromPrimitive;

#[derive(PartialEq, Debug, FromPrimitive)]
pub enum Property {
    END = 0x00,
    Header = 0x01,
    ArchiveProperties = 0x02,
    AdditionalStreamsInfo = 0x03,
    MainStreamsInfo = 0x04,
    FilesInfo = 0x05,
    PackInfo = 0x06,
    UnPackInfo = 0x07,
    SubStreamsInfo = 0x08,
    Size = 0x09,
    CRC = 0x0A,
    Folder = 0x0B,
    CodersUnPackSize = 0x0C,
    NumUnPackStream = 0x0D,
    EmptyStream = 0x0E,
    EmptyFile = 0x0F,
    Anti = 0x10,
    Name = 0x11,
    CTime = 0x12,
    ATime = 0x13,
    MTime = 0x14,
    Attributes = 0x15,
    Comment = 0x16,
    EncodedHeader = 0x17,
    StartPos = 0x18,

    Dummy = 0x19,
}

impl Property {
    pub fn from_u8(value: u8) -> Option<Property> {
        FromPrimitive::from_u8(value)
    }
    pub fn parse(input: &[u8]) -> IResult<&[u8], Property> {
        match le_u8(input) {
            // I'd like to return an IsNot error but I don't know how to do that
            Ok((i, o)) => Ok((i, Self::from_u8(o).expect("Invalid property"))),
            Err(e) => Err(e),
        }
    }
}
