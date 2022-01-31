use crate::{CoderInfo, PackInfo, Property};

pub struct StreamInfo {
    property_id: Property,
    pack_info: PackInfo,
    coder_info: CoderInfo,
    substream_info: SubstreamInfo,
}

impl StreamInfo {}

pub struct SubstreamInfo {}
