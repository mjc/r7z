use super::*;
use crate::folder::FolderGraph;

/// An executable topology with parsed codec properties and admitted memory usage.
pub(crate) struct DecoderPlan {
    topology: Topology,
    memory: WorkingSet,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct WorkingSet(usize);

impl WorkingSet {
    fn add(self, other: Self) -> Result<Self, R7zError> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(R7zError::Decompression)
    }

    fn admit(self) -> Result<Self, R7zError> {
        if self.0 > MAX_DECODER_WORKING_SET_BYTES {
            return Err(resource_limit(
                "decoder working set",
                MAX_DECODER_WORKING_SET_BYTES,
            ));
        }
        Ok(self)
    }

    fn output_limit(self) -> Result<usize, R7zError> {
        MAX_MATERIALIZED_OUTPUT_BYTES
            .checked_sub(self.0)
            .map(growth_safe_output_limit)
            .ok_or_else(|| resource_limit("decoder working set", MAX_MATERIALIZED_OUTPUT_BYTES))
    }
}

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

pub(crate) struct ReadyDecoder<R> {
    topology: BoundTopology<R>,
    memory: WorkingSet,
}

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
                let memory = steps
                    .iter()
                    .try_fold(WorkingSet::default(), |total, step| {
                        total.add(step.working_set(packed_size)?)
                    })?
                    .admit()?;
                Ok(Self {
                    topology: Topology::Chain(steps),
                    memory,
                })
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
                let main = CoderPlan::compile(main.0, main.1)?;
                let call = call
                    .map(|(coder, size)| CoderPlan::compile(coder, size))
                    .transpose()?;
                let jump = jump
                    .map(|(coder, size)| CoderPlan::compile(coder, size))
                    .transpose()?;
                let memory = [
                    (Some(&main), order[0]),
                    (call.as_ref(), order[1]),
                    (jump.as_ref(), order[2]),
                ]
                .into_iter()
                .try_fold(WorkingSet::default(), |total, (coder, index)| {
                    let memory = coder
                        .map(|coder| {
                            let packed = usize::try_from(
                                *packed_sizes
                                    .get(index)
                                    .ok_or(R7zError::InvalidFolderGraph)?,
                            )
                            .map_err(|_| R7zError::Parse)?;
                            coder.working_set(packed)
                        })
                        .transpose()?
                        .unwrap_or_default();
                    total.add(memory)
                })?;
                ensure_bcj2_working_budget(output_size, memory.0)?;
                Ok(Self {
                    topology: Topology::Bcj2 {
                        main,
                        call,
                        jump,
                        order,
                        output_size,
                    },
                    memory,
                })
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
        let bound = match self.topology {
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
        Ok(ReadyDecoder {
            topology: bound,
            memory: self.memory,
        })
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
    pub(super) fn materialize(self, password: Option<&str>) -> Result<Vec<u8>, R7zError> {
        let limit = self.memory.output_limit()?;
        let mut reader = self.start(password)?;
        let mut output = Vec::new();
        read_to_end_bounded(&mut reader, &mut output, limit, "materialized output")?;
        Ok(output)
    }

    pub(crate) fn start<'a>(self, password: Option<&str>) -> Result<FolderReader<'a>, R7zError>
    where
        R: 'a,
    {
        match self.topology {
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
        properties: LzmaProperties,
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
        let properties = || coder.properties.as_deref().ok_or(R7zError::Decompression);
        Ok(match crate::method_from_id(&coder.codec_id) {
            Some(Method::Copy) => Self::Copy,
            Some(Method::Lzma) => Self::Lzma {
                properties: LzmaProperties::parse(properties()?)?,
                size,
            },
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

    fn working_set(&self, packed_input_bytes: usize) -> Result<WorkingSet, R7zError> {
        let bytes = match self {
            Self::Lzma { properties, .. } => properties.memory,
            Self::Lzma2(dictionary) => (*dictionary as usize)
                .checked_add(MAX_LZMA2_PROBABILITY_BYTES)
                .and_then(|n| n.checked_add(DECODER_OVERHEAD_BYTES))
                .ok_or(R7zError::Decompression)?,
            Self::Ppmd { memory, .. } => (*memory as usize)
                .checked_add(DECODER_OVERHEAD_BYTES)
                .ok_or(R7zError::Decompression)?,
            Self::Aes { .. } => packed_input_bytes
                .min(MAX_BUFFERED_AES_BYTES)
                .checked_mul(2)
                .and_then(|n| n.checked_add(DECODER_OVERHEAD_BYTES))
                .ok_or(R7zError::Decompression)?,
            Self::Copy | Self::X86 | Self::Branch(_) | Self::Delta(_) | Self::Swap(_) => 0,
            Self::Arm64(_) | Self::Riscv(_) | Self::Deflate | Self::Bzip2 | Self::Deflate64 => {
                OTHER_CODER_WORKING_SET_BYTES
            }
        };
        Ok(WorkingSet(bytes))
    }

    fn open<'a>(
        self,
        input: Box<dyn Read + 'a>,
        password: Option<&str>,
    ) -> Result<Box<dyn Read + 'a>, R7zError> {
        Ok(match self {
            Self::Copy => input,
            Self::Lzma { properties, size } => Box::new(
                LzmaReader::new(
                    input,
                    size,
                    properties.lc,
                    properties.lp,
                    properties.pb,
                    properties.dictionary,
                    None,
                )
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

/// Validated LZMA parameters shared by memory admission and reader construction.
pub(super) struct LzmaProperties {
    lc: u32,
    lp: u32,
    pb: u32,
    dictionary: u32,
    memory: usize,
}

impl LzmaProperties {
    fn parse(bytes: &[u8]) -> Result<Self, R7zError> {
        let &[props, a, b, c, d] = bytes else {
            return Err(R7zError::Decompression);
        };
        let dictionary = u32::from_le_bytes([a, b, c, d]);
        if dictionary > MAX_LZMA_DICTIONARY_BYTES {
            return Err(resource_limit(
                "LZMA dictionary",
                MAX_LZMA_DICTIONARY_BYTES as usize,
            ));
        }
        if props >= 9 * 5 * 5 {
            return Err(R7zError::Decompression);
        }
        let lc = u32::from(props % 9);
        let lp = u32::from(props / 9 % 5);
        let pb = u32::from(props / (9 * 5));
        let memory_kib = lzma_rust2::lzma_get_memory_usage(dictionary, lc, lp)
            .map_err(|_| R7zError::Decompression)?;
        let memory = usize::try_from(memory_kib)
            .ok()
            .and_then(|n| n.checked_mul(1024))
            .and_then(|n| n.checked_add(DECODER_OVERHEAD_BYTES))
            .ok_or(R7zError::Decompression)?;
        Ok(Self {
            lc,
            lp,
            pb,
            dictionary,
            memory,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coder(bytes: &[u8]) -> crate::CoderInfo {
        crate::CoderInfo::parse(bytes).unwrap().1
    }

    #[test]
    fn typed_codec_plans_preserve_memory_estimates() {
        let lzma2 = CoderPlan::compile(&coder(&[0x21, 0x21, 1, 0]), 0).unwrap();
        assert_eq!(
            lzma2.working_set(0).unwrap().0,
            4096 + MAX_LZMA2_PROBABILITY_BYTES + DECODER_OVERHEAD_BYTES
        );
        let ppmd = CoderPlan::compile(&coder(&[0x23, 3, 4, 1, 5, 6, 0, 0, 16, 0]), 0).unwrap();
        assert_eq!(
            ppmd.working_set(0).unwrap().0,
            1024 * 1024 + DECODER_OVERHEAD_BYTES
        );
        let copy = CoderPlan::compile(&coder(&[1, 0]), 0).unwrap();
        assert_eq!(copy.working_set(usize::MAX).unwrap().0, 0);
    }

    #[test]
    fn aes_working_set_uses_packed_size_and_caps_buffer_estimate() {
        let aes = CoderPlan::compile(&coder(&[0x24, 6, 0xf1, 7, 1, 2, 0, 0]), 0).unwrap();
        for packed in [0, 129 * 1024 * 1024, MAX_BUFFERED_AES_BYTES, usize::MAX] {
            assert_eq!(
                aes.working_set(packed).unwrap().0,
                packed.min(MAX_BUFFERED_AES_BYTES) * 2 + DECODER_OVERHEAD_BYTES
            );
        }
    }

    #[test]
    fn lzma_parameters_and_memory_are_resolved_together() {
        for props in 0..225 {
            let bytes = [props, 0, 0, 16, 0];
            let parsed = LzmaProperties::parse(&bytes).unwrap();
            assert_eq!(
                parsed.lc + 9 * (parsed.lp + 5 * parsed.pb),
                u32::from(props)
            );
            assert_eq!(
                parsed.memory,
                lzma_rust2::lzma_get_memory_usage_by_props(1024 * 1024, props).unwrap() as usize
                    * 1024
                    + DECODER_OVERHEAD_BYTES
            );
        }
        for props in 225..=255 {
            assert!(matches!(
                LzmaProperties::parse(&[props, 0, 0, 16, 0]),
                Err(R7zError::Decompression)
            ));
        }
    }

    #[test]
    fn chained_decoder_state_is_aggregated_before_construction() {
        let lzma2 = || coder(&[0x21, 0x21, 1, 32]);
        let folder = Folder {
            coders: vec![lzma2(), lzma2(), lzma2()].into(),
            bind_pairs: smallvec::smallvec![(1, 0), (2, 1)],
            packed_indices: smallvec::smallvec![0],
        };
        let graph = folder.graph().unwrap();
        assert!(matches!(
            DecoderPlan::compile(&folder, &graph, 0, &[0; 3], &[0]),
            Err(R7zError::ResourceLimitExceeded {
                resource: "decoder working set",
                ..
            })
        ));
    }

    #[test]
    fn bound_decoder_keeps_admitted_memory_for_output_budget() {
        let folder = Folder::parse(&[1, 0x21, 0x21, 1, 0]).unwrap().1;
        let graph = folder.graph().unwrap();
        let plan = DecoderPlan::compile(&folder, &graph, 0, &[0], &[1]).unwrap();
        let expected = plan.memory;
        let ready = plan
            .bind(smallvec::smallvec![PackedInput {
                reader: Cursor::new([0]),
                size: 1
            }])
            .unwrap();
        assert_eq!(ready.memory, expected);
        assert_eq!(
            ready.memory.output_limit().unwrap(),
            (MAX_MATERIALIZED_OUTPUT_BYTES - expected.0) / 2
        );
        assert!(ready.materialize(None).unwrap().is_empty());
    }
}
