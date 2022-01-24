mod signature_header;
pub use signature_header::*;

// My understanding of the simplest layout:
// SignatureHeader
//     (data block
//         (packed stream)
//             packed substream
//         (packed stream)
//             (packed substream)
//         (...))
//     (packed stream for header
//     header encoding information)
//     header
