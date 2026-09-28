use super::*;
use crate::folder::FolderGraph;

/// An executable topology with parsed codec properties and admitted memory usage.
pub(crate) struct DecoderPlan(Topology);

enum Topology {
    Chain(SmallVec<[CoderPlan; 4]>),
    Bcj2 {
        main: CoderPlan,
        call: Option<CoderPlan>,
        jump: Option<CoderPlan>,
        order: [usize; 4],
        output_size: usize,
    },
}

pub(crate) struct ReadyDecoder<R>(BoundTopology<R>);

enum BoundTopology<R> {
    Chain {
        steps: SmallVec<[CoderPlan; 4]>,
        input: R,
    },
    Bcj2 {
        main: BoundInput<R>,
        call: BoundInput<R>,
        jump: BoundInput<R>,
        control: R,
        output_size: usize,
    },
}

struct BoundInput<R> {
    input: R,
    coder: Option<CoderPlan>,
}

impl DecoderPlan {
    pub(crate) fn compile(
        folder: &Folder,
        graph: &FolderGraph,
        unpack_size: u64,
        sizes: &[u64],
        packed_sizes: &[u64],
    ) -> Result<Self, R7zError> {
        validate_folder_coder_count(folder)?;
        if graph.packed_stream_count() != packed_sizes.len()
            || sizes.len() != folder.total_out_streams()
        {
            return Err(R7zError::InvalidFolderGraph);
        }
        match DecoderTopology::from_folder(folder)? {
            DecoderTopology::Chain => {
                let packed_size =
                    usize::try_from(*packed_sizes.first().ok_or(R7zError::InvalidFolderGraph)?)
                        .map_err(|_| R7zError::Parse)?;
                validate_decoder_working_set(folder, packed_size)?;
                let steps = graph
                    .execution_order()
                    .map(|index| {
                        let index = index.get();
                        CoderPlan::compile(
                            folder
                                .coders
                                .get(index)
                                .ok_or(R7zError::InvalidFolderGraph)?,
                            *sizes.get(index).ok_or(R7zError::Parse)?,
                        )
                    })
                    .collect::<Result<SmallVec<[_; 4]>, _>>()?;
                Ok(Self(Topology::Chain(steps)))
            }
            DecoderTopology::Bcj2 => {
                let output_size = bcj2_output_size(unpack_size)?;
                let (main, call, jump, order) = match (
                    folder.coders.as_slice(),
                    folder.packed_indices.as_slice(),
                    folder.bind_pairs.as_slice(),
                    sizes,
                    packed_sizes,
                ) {
                    (
                        [main, _],
                        [0, 2, 3, 4],
                        [(1, 0)],
                        [main_size, _],
                        [_, call_size, jump_size, _],
                    ) => {
                        let declared = main_size
                            .checked_add(*call_size)
                            .and_then(|n| n.checked_add(*jump_size))
                            .ok_or(R7zError::Decompression)?;
                        if declared != unpack_size {
                            return Err(R7zError::Decompression);
                        }
                        ((main, *main_size), None, None, [0, 1, 2, 3])
                    }
                    (
                        [jump, call, main, _],
                        [2, 6, 1, 0],
                        [(5, 0), (4, 1), (3, 2)],
                        [jump_size, call_size, main_size, _],
                        [_, _, _, _],
                    ) => (
                        (main, *main_size),
                        Some((call, *call_size)),
                        Some((jump, *jump_size)),
                        [0, 2, 3, 1],
                    ),
                    _ => return Err(R7zError::Parse),
                };
                let decoder_memory = [(Some(main), order[0]), (call, order[1]), (jump, order[2])]
                    .into_iter()
                    .try_fold(0usize, |total, (coder, index)| {
                        let memory = coder
                            .map(|(coder, _)| {
                                let packed = usize::try_from(
                                    *packed_sizes
                                        .get(index)
                                        .ok_or(R7zError::InvalidFolderGraph)?,
                                )
                                .map_err(|_| R7zError::Parse)?;
                                coder_working_set_bytes(coder, packed)
                            })
                            .transpose()?
                            .unwrap_or(0);
                        total.checked_add(memory).ok_or(R7zError::Decompression)
                    })?;
                ensure_bcj2_working_budget(output_size, decoder_memory)?;
                Ok(Self(Topology::Bcj2 {
                    main: CoderPlan::compile(main.0, main.1)?,
                    call: call
                        .map(|(coder, size)| CoderPlan::compile(coder, size))
                        .transpose()?,
                    jump: jump
                        .map(|(coder, size)| CoderPlan::compile(coder, size))
                        .transpose()?,
                    order,
                    output_size,
                }))
            }
        }
    }

    pub(crate) fn bind<R>(
        self,
        inputs: SmallVec<[PackedInput<R>; 4]>,
    ) -> Result<ReadyDecoder<R>, R7zError> {
        let mut inputs = inputs
            .into_iter()
            .map(|input| Some(input.reader))
            .collect::<SmallVec<[_; 4]>>();
        let bound = match self.0 {
            Topology::Chain(steps) => match inputs.as_mut_slice() {
                [input] => BoundTopology::Chain {
                    steps,
                    input: input.take().ok_or(R7zError::InvalidFolderGraph)?,
                },
                _ => return Err(R7zError::InvalidFolderGraph),
            },
            Topology::Bcj2 {
                main,
                call,
                jump,
                order,
                output_size,
            } => {
                if inputs.len() != 4 {
                    return Err(R7zError::InvalidFolderGraph);
                }
                let mut take = |index| {
                    inputs
                        .get_mut(index)
                        .and_then(Option::take)
                        .ok_or(R7zError::InvalidFolderGraph)
                };
                BoundTopology::Bcj2 {
                    main: BoundInput {
                        input: take(order[0])?,
                        coder: Some(main),
                    },
                    call: BoundInput {
                        input: take(order[1])?,
                        coder: call,
                    },
                    jump: BoundInput {
                        input: take(order[2])?,
                        coder: jump,
                    },
                    control: take(order[3])?,
                    output_size,
                }
            }
        };
        Ok(ReadyDecoder(bound))
    }
}

impl<R: Read> BoundInput<R> {
    fn open<'a>(self, password: Option<&str>) -> Result<Box<dyn Read + 'a>, R7zError>
    where
        R: 'a,
    {
        let reader = Box::new(self.input) as Box<dyn Read>;
        match self.coder {
            Some(coder) => coder.open(reader, password),
            None => Ok(reader),
        }
    }
}

impl<R: Read> ReadyDecoder<R> {
    pub(crate) fn start<'a>(self, password: Option<&str>) -> Result<FolderReader<'a>, R7zError>
    where
        R: 'a,
    {
        match self.0 {
            BoundTopology::Chain { steps, input } => {
                let mut reader: Box<dyn Read + 'a> = Box::new(input);
                for step in steps {
                    reader = step.open(reader, password)?;
                }
                Ok(FolderReader::Stream(reader))
            }
            BoundTopology::Bcj2 {
                main,
                call,
                jump,
                control,
                output_size,
            } => crate::bcj2::decode(
                main.open(password)?,
                call.open(password)?,
                jump.open(password)?,
                Box::new(control),
                output_size,
            )
            .map(|bytes| FolderReader::Buffered(Cursor::new(bytes))),
        }
    }
}

pub(super) enum CoderPlan {
    Copy,
    Lzma {
        props: u8,
        dictionary: u32,
        size: u64,
    },
    Lzma2(u32),
    X86,
    Branch(crate::bcj::BranchFilter),
    Arm64(usize),
    Riscv(usize),
    Deflate,
    Bzip2,
    Ppmd {
        order: u32,
        memory: u32,
        size: u64,
    },
    Deflate64,
    Delta(u8),
    Swap(usize),
    Aes {
        properties: crate::aes::AesProperties,
        size: u64,
    },
}

impl CoderPlan {
    pub(super) fn compile(coder: &crate::CoderInfo, size: u64) -> Result<Self, R7zError> {
        use crate::SevenZMethod as Method;
        coder_working_set_bytes(coder, 0)?;
        let properties = || coder.properties.as_deref().ok_or(R7zError::Decompression);
        Ok(match crate::method_from_id(&coder.codec_id) {
            Some(Method::Copy) => Self::Copy,
            Some(Method::Lzma) => {
                let &[props, a, b, c, d] = properties()? else {
                    return Err(R7zError::Decompression);
                };
                Self::Lzma {
                    props,
                    dictionary: u32::from_le_bytes([a, b, c, d]),
                    size,
                }
            }
            Some(Method::Lzma2) => Self::Lzma2(lzma2_dict_size(coder.properties.as_deref())?),
            Some(Method::Bcj) => Self::X86,
            Some(Method::Arm) => Self::Branch(crate::bcj::BranchFilter::Arm),
            Some(Method::ArmThumb) => Self::Branch(crate::bcj::BranchFilter::ArmThumb),
            Some(Method::Ia64) => Self::Branch(crate::bcj::BranchFilter::Ia64),
            Some(Method::Ppc) => Self::Branch(crate::bcj::BranchFilter::Ppc),
            Some(Method::Sparc) => Self::Branch(crate::bcj::BranchFilter::Sparc),
            Some(Method::Arm64) => Self::Arm64(branch_start_pos(coder.properties.as_deref(), 4)?),
            Some(Method::Riscv) => Self::Riscv(branch_start_pos(coder.properties.as_deref(), 2)?),
            Some(Method::Deflate) => Self::Deflate,
            Some(Method::BZip2) => Self::Bzip2,
            Some(Method::Ppmd) => {
                let (order, memory) = ppmd_properties(properties()?)?;
                Self::Ppmd {
                    order,
                    memory,
                    size,
                }
            }
            Some(Method::Deflate64) => Self::Deflate64,
            Some(Method::Delta) => {
                let &[distance] = properties()? else {
                    return Err(R7zError::Decompression);
                };
                Self::Delta(distance)
            }
            Some(Method::Swap2) => Self::Swap(2),
            Some(Method::Swap4) => Self::Swap(4),
            Some(Method::SevenZAes) => Self::Aes {
                properties: crate::aes::AesProperties::parse(properties()?)?,
                size,
            },
            _ => return Err(R7zError::UnsupportedCodec(coder.codec_id.to_vec())),
        })
    }

    fn open<'a>(
        self,
        input: Box<dyn Read + 'a>,
        password: Option<&str>,
    ) -> Result<Box<dyn Read + 'a>, R7zError> {
        Ok(match self {
            Self::Copy => input,
            Self::Lzma {
                props,
                dictionary,
                size,
            } => Box::new(
                LzmaReader::new_with_props(input, size, props, dictionary, None)
                    .map_err(|_| R7zError::Decompression)?,
            ),
            Self::Lzma2(dictionary) => Box::new(Lzma2Reader::new(input, dictionary, None)),
            Self::X86 => Box::new(crate::bcj::BcjX86Reader::new(input)),
            Self::Branch(filter) => Box::new(crate::bcj::BranchReader::new(input, filter)),
            Self::Arm64(position) => Box::new(BcjReader::new_arm64(input, position)),
            Self::Riscv(position) => Box::new(BcjReader::new_riscv(input, position)),
            Self::Deflate => Box::new(DeflateDecoder::new(input)),
            Self::Bzip2 => Box::new(Bzip2Decoder::new(input)),
            Self::Ppmd {
                order,
                memory,
                size,
            } => Box::new(ExactSizeReader::new(
                Ppmd7Decoder::new(input, order, memory).map_err(|_| R7zError::Decompression)?,
                size,
            )),
            Self::Deflate64 => Box::new(Deflate64Decoder::new(input)),
            Self::Delta(distance) => Box::new(crate::delta::DeltaReader::new(input, &[distance])?),
            Self::Swap(width) => Box::new(crate::byte_swap::ByteSwapReader::new(input, width)),
            Self::Aes { properties, size } => aes_coder_reader(properties, input, size, password)?,
        })
    }
}
