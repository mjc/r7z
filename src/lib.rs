extern crate num;
#[macro_use]
extern crate num_derive;

mod signature_header;
pub use signature_header::*;

mod property;
pub use property::Property;

/*
My understanding of the simplest layout:
SignatureHeader
    (data block
        (packed stream)
            packed substream
        (packed stream)
            (packed substream)
        (...))
    (packed stream for header
    header encoding information)
    header
*/
