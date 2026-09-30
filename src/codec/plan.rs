use super::*;
use crate::folder::{Bcj2Layout, FolderGraph, PackedStreamIndex};
use crate::resources::OperationBudget;

/// An executable topology with parsed codec properties and admitted memory usage.
pub(crate) struct DecoderPlan<'a> {
    topology: Topology,
    memory: WorkingSet,
    inputs: PackedLayout<'a>,
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

    fn admit(self, configured_limit: Option<u64>) -> Result<Self, R7zError> {
        let limit = configured_limit.map_or(MAX_DECODER_WORKING_SET_BYTES as u64, |limit| {
            limit.min(MAX_DECODER_WORKING_SET_BYTES as u64)
        }) as usize;
        if self.0 > limit {
            return Err(resource_limit("decoder working set", limit));
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
    Chain(SmallVec<[DecodeStep; 2]>),
    Bcj2 {
        main: Vec<DecodeStep>,
        call: Vec<DecodeStep>,
        jump: Vec<DecodeStep>,
        control: Vec<DecodeStep>,
        slots: Bcj2Slots,
        output_size: usize,
    },
}

enum DecoderTopology {
    Chain,
    Bcj2(Bcj2Layout),
}

pub(crate) struct ReadyDecoder<R> {
    topology: BoundTopology<std::io::Take<R>>,
    memory: WorkingSet,
}

enum BoundTopology<R> {
    Chain {
        steps: SmallVec<[DecodeStep; 2]>,
        input: R,
    },
    Bcj2(Box<BoundBcj2<R>>),
}

struct BoundBcj2<R> {
    main: BoundInput<R>,
    call: BoundInput<R>,
    jump: BoundInput<R>,
    control: BoundInput<R>,
    output_size: usize,
}

struct BoundInput<R> {
    input: R,
    coders: Vec<DecodeStep>,
}

/// An ordinal in the folder's packed-input list, independent of coder indexes.
#[derive(Clone, Copy)]
struct PackedInputSlot(usize);

struct Bcj2Slots {
    main: PackedInputSlot,
    call: PackedInputSlot,
    jump: PackedInputSlot,
    control: PackedInputSlot,
}

struct PackedLayout<'a> {
    sizes: &'a [u64],
}

fn decoder_topology(folder: &Folder, graph: &FolderGraph) -> Result<DecoderTopology, R7zError> {
    match graph.bcj2_layout(folder)? {
        Some(layout) => {
            let bcj2 = folder
                .coders
                .iter()
                .find(|coder| coder.codec_id.as_slice() == crate::CODEC_BCJ2)
                .ok_or(R7zError::InvalidFolderGraph)?;
            no_properties(bcj2)?;
            Ok(DecoderTopology::Bcj2(layout))
        }
        None => {
            let unknown_method = folder
                .coders
                .iter()
                .find(|coder| crate::method_from_id(&coder.codec_id).is_none());
            match unknown_method {
                Some(coder) => Err(R7zError::UnsupportedCodec(coder.codec_id.to_vec())),
                None if folder
                    .coders
                    .iter()
                    .all(|coder| coder.num_in_streams == 1 && coder.num_out_streams == 1) =>
                {
                    Ok(DecoderTopology::Chain)
                }
                None => Err(R7zError::InvalidFolderGraph),
            }
        }
    }
}

fn no_properties(coder: &crate::CoderInfo) -> Result<(), R7zError> {
    match coder.properties.as_deref() {
        None | Some([]) => Ok(()),
        Some(_) => Err(R7zError::Decompression),
    }
}

/// Readers checked against the planned list and bounded to its byte lengths.
struct BoundInputs<R>(SmallVec<[Option<std::io::Take<R>>; 4]>);

impl PackedLayout<'_> {
    fn size(&self, slot: PackedInputSlot) -> Result<usize, R7zError> {
        usize::try_from(*self.sizes.get(slot.0).ok_or(R7zError::InvalidFolderGraph)?)
            .map_err(|_| R7zError::Parse)
    }

    fn bind<R: Read>(
        self,
        inputs: SmallVec<[PackedInput<R>; 4]>,
    ) -> Result<BoundInputs<R>, R7zError> {
        if inputs.len() != self.sizes.len() {
            return Err(R7zError::InvalidFolderGraph);
        }
        if inputs
            .iter()
            .zip(self.sizes)
            .any(|(input, &size)| input.size as u64 != size)
        {
            return Err(R7zError::Parse);
        }
        Ok(BoundInputs(
            inputs
                .into_iter()
                .zip(self.sizes)
                .map(|(input, &size)| Some(input.reader.take(size)))
                .collect(),
        ))
    }
}

impl<R> BoundInputs<R> {
    fn take(&mut self, slot: PackedInputSlot) -> Result<std::io::Take<R>, R7zError> {
        self.0
            .get_mut(slot.0)
            .and_then(Option::take)
            .ok_or(R7zError::InvalidFolderGraph)
    }
}

impl<'a> DecoderPlan<'a> {
    #[cfg(test)]
    pub(crate) fn compile(
        folder: &Folder,
        graph: &FolderGraph,
        unpack_size: u64,
        sizes: &[u64],
        packed_sizes: &'a [u64],
    ) -> Result<Self, R7zError> {
        Self::compile_with_working_set_limit(folder, graph, unpack_size, sizes, packed_sizes, None)
    }

    pub(crate) fn compile_with_working_set_limit(
        folder: &Folder,
        graph: &FolderGraph,
        unpack_size: u64,
        sizes: &[u64],
        packed_sizes: &'a [u64],
        max_working_set_bytes: Option<u64>,
    ) -> Result<Self, R7zError> {
        let sizes = CoderOutputSizes::complete(folder, graph, unpack_size, sizes)?;
        Self::with_output_sizes(
            folder,
            graph,
            unpack_size,
            sizes,
            packed_sizes,
            max_working_set_bytes,
        )
    }

    pub(super) fn with_output_sizes(
        folder: &Folder,
        graph: &FolderGraph,
        unpack_size: u64,
        sizes: CoderOutputSizes<'_>,
        packed_sizes: &'a [u64],
        max_working_set_bytes: Option<u64>,
    ) -> Result<Self, R7zError> {
        validate_folder_coder_count(folder)?;
        if graph.packed_stream_count() != packed_sizes.len() {
            return Err(R7zError::InvalidFolderGraph);
        }
        let inputs = PackedLayout {
            sizes: packed_sizes,
        };
        match decoder_topology(folder, graph)? {
            DecoderTopology::Chain => {
                let [packed_size] = packed_sizes else {
                    return Err(R7zError::InvalidFolderGraph);
                };
                let packed_size = OutputSize::Known(*packed_size);
                // Length-preserving filters let the final size resolve omitted predecessors.
                let mut next_input = OutputSize::Unknown;
                let mut steps = graph
                    .execution_order()
                    .rev()
                    .map(|index| {
                        let index = index.get();
                        let coder = folder
                            .coders
                            .get(index)
                            .ok_or(R7zError::InvalidFolderGraph)?;
                        let output = sizes.get(index).reconcile(next_input)?;
                        let step = SizedCoder::compile(coder, output)?;
                        next_input = if step.coder.preserves_size() {
                            output
                        } else {
                            OutputSize::Unknown
                        };
                        Ok(step)
                    })
                    .collect::<Result<SmallVec<[_; 2]>, R7zError>>()?;
                steps.reverse();
                let mut input_size = packed_size;
                let steps = steps
                    .into_iter()
                    .map(|step| {
                        let step = step.bind_size(input_size)?;
                        input_size = step.output;
                        Ok(step)
                    })
                    .collect::<Result<SmallVec<[_; 2]>, R7zError>>()?;
                let memory = steps
                    .iter()
                    .try_fold(WorkingSet::default(), |total, step| {
                        total.add(step.working_set()?)
                    })?
                    .admit(max_working_set_bytes)?;
                Ok(Self {
                    topology: Topology::Chain(steps),
                    memory,
                    inputs,
                })
            }
            DecoderTopology::Bcj2(layout) => {
                let output_size = bcj2_output_size(unpack_size)?;
                let slot = |packed: PackedStreamIndex| PackedInputSlot(packed.get());
                let compile_channel =
                    |channel: &crate::folder::Bcj2Channel, packed: PackedInputSlot| {
                        let mut input_size = OutputSize::Known(inputs.size(packed)? as u64);
                        channel
                            .coders
                            .iter()
                            .map(|channel_coder| {
                                let coder = folder
                                    .coders
                                    .get(channel_coder.index.get())
                                    .ok_or(R7zError::InvalidFolderGraph)?;
                                let step = SizedCoder::compile(
                                    coder,
                                    sizes.get(channel_coder.output.get()),
                                )?
                                .bind_size(input_size)?;
                                input_size = step.output;
                                Ok(step)
                            })
                            .collect::<Result<Vec<_>, R7zError>>()
                    };
                let slots = Bcj2Slots {
                    main: slot(layout.main.packed),
                    call: slot(layout.call.packed),
                    jump: slot(layout.jump.packed),
                    control: slot(layout.control.packed),
                };
                let main = compile_channel(&layout.main, slots.main)?;
                let call = compile_channel(&layout.call, slots.call)?;
                let jump = compile_channel(&layout.jump, slots.jump)?;
                let control = compile_channel(&layout.control, slots.control)?;
                let data_channels = [
                    (&main, slots.main),
                    (&call, slots.call),
                    (&jump, slots.jump),
                ];
                let declared =
                    data_channels
                        .into_iter()
                        .try_fold(0u64, |total, (coders, slot)| {
                            let output = coders.last().map_or_else(
                                || Ok(inputs.size(slot)? as u64),
                                |coder| coder.output.require(),
                            )?;
                            total.checked_add(output).ok_or(R7zError::Decompression)
                        })?;
                if declared != unpack_size {
                    return Err(R7zError::Decompression);
                }
                let memory = [&main, &call, &jump, &control]
                    .into_iter()
                    .flatten()
                    .try_fold(WorkingSet::default(), |total, coder| {
                        total.add(coder.working_set()?)
                    })?;
                ensure_bcj2_working_budget(output_size, memory.0)?;
                let memory = memory
                    .add(WorkingSet(output_size))?
                    .admit(max_working_set_bytes)?;
                Ok(Self {
                    topology: Topology::Bcj2 {
                        main,
                        call,
                        jump,
                        control,
                        slots,
                        output_size,
                    },
                    memory,
                    inputs,
                })
            }
        }
    }

    pub(crate) fn bind<R: Read>(
        self,
        inputs: SmallVec<[PackedInput<R>; 4]>,
    ) -> Result<ReadyDecoder<R>, R7zError> {
        let mut inputs = self.inputs.bind(inputs)?;
        let bound = match self.topology {
            Topology::Chain(steps) => BoundTopology::Chain {
                steps,
                input: inputs.take(PackedInputSlot(0))?,
            },
            Topology::Bcj2 {
                main,
                call,
                jump,
                control,
                slots,
                output_size,
            } => BoundTopology::Bcj2(Box::new(BoundBcj2 {
                main: BoundInput {
                    input: inputs.take(slots.main)?,
                    coders: main,
                },
                call: BoundInput {
                    input: inputs.take(slots.call)?,
                    coders: call,
                },
                jump: BoundInput {
                    input: inputs.take(slots.jump)?,
                    coders: jump,
                },
                control: BoundInput {
                    input: inputs.take(slots.control)?,
                    coders: control,
                },
                output_size,
            })),
        };
        Ok(ReadyDecoder {
            topology: bound,
            memory: self.memory,
        })
    }
}

impl<R: Read> BoundInput<R> {
    fn open<'a>(
        self,
        password: Option<&str>,
        budget: &mut OperationBudget,
    ) -> Result<Box<dyn Read + 'a>, R7zError>
    where
        R: 'a,
    {
        self.coders.into_iter().try_fold(
            Box::new(self.input) as Box<dyn Read + 'a>,
            |reader, coder| coder.open(reader, password, budget),
        )
    }
}

impl<R: Read> ReadyDecoder<R> {
    pub(crate) fn eager_output_size(&self) -> Option<u64> {
        match &self.topology {
            BoundTopology::Bcj2(bcj2) => Some(bcj2.output_size as u64),
            BoundTopology::Chain { steps, .. } => {
                steps.iter().enumerate().rev().find_map(|(index, step)| {
                    let eager_final_output = matches!(&step.coder, CoderPlan::Aes(_))
                        && steps[index + 1..]
                            .iter()
                            .all(|following| following.coder.preserves_size());
                    eager_final_output
                        .then_some(step.output)
                        .and_then(|output| match output {
                            OutputSize::Known(size) => Some(size),
                            OutputSize::Unknown => None,
                        })
                })
            }
        }
    }

    pub(super) fn materialize(
        self,
        password: Option<&str>,
        budget: &mut OperationBudget,
    ) -> Result<Vec<u8>, R7zError> {
        let limit = self.memory.output_limit()?;
        let mut reader = self.start(password, budget)?;
        let mut output = Vec::new();
        read_to_end_bounded(&mut reader, &mut output, limit, "materialized output")?;
        Ok(output)
    }

    pub(crate) fn start<'a>(
        self,
        password: Option<&str>,
        budget: &mut OperationBudget,
    ) -> Result<FolderReader<'a>, R7zError>
    where
        R: 'a,
    {
        match self.topology {
            BoundTopology::Chain { steps, input } => {
                let mut reader: Box<dyn Read + 'a> = Box::new(input);
                for step in steps {
                    reader = step.open(reader, password, budget)?;
                }
                Ok(FolderReader::Stream(reader))
            }
            BoundTopology::Bcj2(bcj2) => crate::bcj2::decode(
                bcj2.main.open(password, budget)?,
                bcj2.call.open(password, budget)?,
                bcj2.jump.open(password, budget)?,
                bcj2.control.open(password, budget)?,
                bcj2.output_size,
            )
            .map(|bytes| FolderReader::Buffered(Cursor::new(bytes))),
        }
    }
}

/// Parsed properties with an output size resolved from the folder's graph.
struct SizedCoder {
    coder: CoderPlan,
    output: OutputSize,
}

impl SizedCoder {
    fn compile(coder: &crate::CoderInfo, output: OutputSize) -> Result<Self, R7zError> {
        Ok(Self {
            coder: CoderPlan::compile(coder, output)?,
            output,
        })
    }

    fn bind_size(self, input: OutputSize) -> Result<DecodeStep, R7zError> {
        let output = if self.coder.preserves_size() {
            self.output.reconcile(input)?
        } else {
            self.output
        };
        Ok(DecodeStep {
            coder: self.coder,
            input,
            output,
        })
    }
}

/// Input and output sizes resolved before resource admission and reader construction.
struct DecodeStep {
    coder: CoderPlan,
    input: OutputSize,
    output: OutputSize,
}

impl DecodeStep {
    fn working_set(&self) -> Result<WorkingSet, R7zError> {
        self.coder.working_set()
    }

    fn open<'r>(
        self,
        input: Box<dyn Read + 'r>,
        password: Option<&str>,
        budget: &mut OperationBudget,
    ) -> Result<Box<dyn Read + 'r>, R7zError> {
        self.coder
            .open(input, self.input, self.output, password, budget)
    }
}

pub(super) enum CoderPlan {
    Copy,
    Lzma(LzmaProperties),
    Lzma2(u32),
    X86,
    Branch(crate::bcj::BranchFilter),
    Arm64(usize),
    Riscv(usize),
    Deflate,
    Bzip2,
    Ppmd { order: u32, memory: u32, size: u64 },
    Deflate64,
    Delta(u8),
    Swap(usize),
    Aes(crate::aes::AesProperties),
}

impl CoderPlan {
    pub(super) fn compile(coder: &crate::CoderInfo, size: OutputSize) -> Result<Self, R7zError> {
        use crate::SevenZMethod as Method;
        let properties = || coder.properties.as_deref().ok_or(R7zError::Decompression);
        let info = crate::method_info(&coder.codec_id)
            .filter(|info| info.can_decode())
            .ok_or_else(|| R7zError::UnsupportedCodec(coder.codec_id.to_vec()))?;
        Ok(match info.method {
            Method::Copy => {
                no_properties(coder)?;
                Self::Copy
            }
            Method::Lzma => Self::Lzma(LzmaProperties::parse(properties()?)?),
            Method::Lzma2 => Self::Lzma2(lzma2_dict_size(coder.properties.as_deref())?),
            Method::Bcj => {
                no_properties(coder)?;
                Self::X86
            }
            Method::Arm => {
                no_properties(coder)?;
                Self::Branch(crate::bcj::BranchFilter::Arm)
            }
            Method::ArmThumb => {
                no_properties(coder)?;
                Self::Branch(crate::bcj::BranchFilter::ArmThumb)
            }
            Method::Ia64 => {
                no_properties(coder)?;
                Self::Branch(crate::bcj::BranchFilter::Ia64)
            }
            Method::Ppc => {
                no_properties(coder)?;
                Self::Branch(crate::bcj::BranchFilter::Ppc)
            }
            Method::Sparc => {
                no_properties(coder)?;
                Self::Branch(crate::bcj::BranchFilter::Sparc)
            }
            Method::Arm64 => Self::Arm64(branch_start_pos(coder.properties.as_deref(), 4)?),
            Method::Riscv => Self::Riscv(branch_start_pos(coder.properties.as_deref(), 2)?),
            Method::Deflate => {
                no_properties(coder)?;
                Self::Deflate
            }
            Method::BZip2 => {
                no_properties(coder)?;
                Self::Bzip2
            }
            Method::Ppmd => {
                let (order, memory) = ppmd_properties(properties()?)?;
                Self::Ppmd {
                    order,
                    memory,
                    size: size.require()?,
                }
            }
            Method::Deflate64 => {
                no_properties(coder)?;
                Self::Deflate64
            }
            Method::Delta => {
                let &[distance] = properties()? else {
                    return Err(R7zError::Decompression);
                };
                Self::Delta(distance)
            }
            Method::Swap2 => {
                no_properties(coder)?;
                Self::Swap(2)
            }
            Method::Swap4 => {
                no_properties(coder)?;
                Self::Swap(4)
            }
            Method::SevenZAes => Self::Aes(crate::aes::AesProperties::parse(properties()?)?),
            _ => return Err(R7zError::UnsupportedCodec(coder.codec_id.to_vec())),
        })
    }

    fn working_set(&self) -> Result<WorkingSet, R7zError> {
        let bytes = match self {
            Self::Lzma(properties) => properties.memory,
            Self::Lzma2(dictionary) => (*dictionary as usize)
                .checked_add(MAX_LZMA2_PROBABILITY_BYTES)
                .and_then(|n| n.checked_add(DECODER_OVERHEAD_BYTES))
                .ok_or(R7zError::Decompression)?,
            Self::Ppmd { memory, .. } => (*memory as usize)
                .checked_add(DECODER_OVERHEAD_BYTES)
                .ok_or(R7zError::Decompression)?,
            Self::Aes(_) => AES_CBC_WORKING_SET_BYTES
                .checked_add(DECODER_OVERHEAD_BYTES)
                .ok_or(R7zError::Decompression)?,
            Self::Copy | Self::X86 | Self::Branch(_) | Self::Delta(_) | Self::Swap(_) => 0,
            Self::Arm64(_) | Self::Riscv(_) | Self::Deflate | Self::Bzip2 | Self::Deflate64 => {
                OTHER_CODER_WORKING_SET_BYTES
            }
        };
        Ok(WorkingSet(bytes))
    }

    fn preserves_size(&self) -> bool {
        matches!(
            self,
            Self::Copy
                | Self::X86
                | Self::Branch(_)
                | Self::Arm64(_)
                | Self::Riscv(_)
                | Self::Delta(_)
                | Self::Swap(_)
        )
    }

    fn open<'a>(
        self,
        input: Box<dyn Read + 'a>,
        input_size: OutputSize,
        output: OutputSize,
        password: Option<&str>,
        budget: &mut OperationBudget,
    ) -> Result<Box<dyn Read + 'a>, R7zError> {
        Ok(match self {
            Self::Copy => match output {
                OutputSize::Known(size) => Box::new(ExactSizeReader::terminated(input, size)),
                OutputSize::Unknown => input,
            },
            Self::Lzma(properties) => checked_reader(
                LzmaReader::new(
                    input,
                    match output {
                        OutputSize::Known(size) => size,
                        OutputSize::Unknown => u64::MAX,
                    },
                    properties.lc,
                    properties.lp,
                    properties.pb,
                    properties.dictionary,
                    None,
                )
                .map_err(|_| R7zError::Decompression)?,
                output,
            ),
            Self::Lzma2(dictionary) => {
                checked_reader(Lzma2Reader::new(input, dictionary, None), output)
            }
            Self::X86 => checked_reader(crate::bcj::BcjX86Reader::new(input), output),
            Self::Branch(filter) => {
                checked_reader(crate::bcj::BranchReader::new(input, filter), output)
            }
            Self::Arm64(position) => checked_reader(BcjReader::new_arm64(input, position), output),
            Self::Riscv(position) => checked_reader(BcjReader::new_riscv(input, position), output),
            Self::Deflate => checked_reader(DeflateDecoder::new(input), output),
            Self::Bzip2 => checked_reader(Bzip2Decoder::new(input), output),
            Self::Ppmd {
                order,
                memory,
                size,
            } => Box::new(ExactSizeReader::sized(
                Ppmd7Decoder::new(input, order, memory).map_err(|_| R7zError::Decompression)?,
                size,
            )),
            Self::Deflate64 => checked_reader(Deflate64Decoder::new(input), output),
            Self::Delta(distance) => {
                checked_reader(crate::delta::DeltaReader::new(input, &[distance])?, output)
            }
            Self::Swap(width) => {
                checked_reader(crate::byte_swap::ByteSwapReader::new(input, width), output)
            }
            Self::Aes(properties) => checked_reader(
                aes_coder_reader(properties, input, input_size, output, password, budget)?,
                output,
            ),
        })
    }
}

fn checked_reader<'a>(reader: impl Read + 'a, output: OutputSize) -> Box<dyn Read + 'a> {
    match output {
        OutputSize::Known(size) => Box::new(ExactSizeReader::terminated(reader, size)),
        OutputSize::Unknown => Box::new(reader),
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

    fn operation_budget() -> OperationBudget {
        OperationBudget::new(crate::resources::ResourceLimits::default())
    }

    struct Unreadable(usize);

    impl Read for Unreadable {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("binding must not read input {}", self.0);
        }
    }

    #[test]
    fn binding_rejects_counts_and_sizes_before_reading() {
        let folder = Folder::parse(&[1, 1, 0]).unwrap().1;
        let graph = folder.graph().unwrap();
        for sizes in [&[][..], &[3, 3][..], &[2][..], &[4][..]] {
            let plan = DecoderPlan::compile(&folder, &graph, 3, &[3], &[3]).unwrap();
            let inputs = sizes
                .iter()
                .enumerate()
                .map(|(index, &size)| PackedInput {
                    reader: Unreadable(index),
                    size,
                })
                .collect();
            let result = plan.bind(inputs);
            match sizes.len() {
                1 => assert!(matches!(result, Err(R7zError::Parse))),
                _ => assert!(matches!(result, Err(R7zError::InvalidFolderGraph))),
            }
        }
    }

    #[test]
    fn binding_bounds_readers_to_the_admitted_bytes() {
        let folder = Folder::parse(&[1, 1, 0]).unwrap().1;
        let graph = folder.graph().unwrap();
        let plan = DecoderPlan::compile(&folder, &graph, 3, &[3], &[3]).unwrap();
        let mut budget = operation_budget();
        let mut input = Cursor::new(b"abcEXTRA");
        let output = plan
            .bind(smallvec::smallvec![PackedInput {
                reader: &mut input,
                size: 3
            }])
            .unwrap()
            .materialize(None, &mut budget)
            .unwrap();
        assert_eq!(output, b"abc");
        assert_eq!(input.position(), 3);

        let plan = DecoderPlan::compile(&folder, &graph, 0, &[0], &[0]).unwrap();
        let mut budget = operation_budget();
        let output = plan
            .bind(smallvec::smallvec![PackedInput {
                reader: Unreadable(0),
                size: 0
            }])
            .unwrap()
            .materialize(None, &mut budget)
            .unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn bcj2_binding_preserves_named_slots_and_checks_every_size() {
        let copy = || coder(&[1, 0]);
        let bcj2 = || coder(&[0x14, 3, 3, 1, 0x1b, 4, 1]);
        let layouts = [
            (
                Folder {
                    coders: smallvec::smallvec![copy(), bcj2()],
                    packed_indices: smallvec::smallvec![0, 2, 3, 4],
                    bind_pairs: smallvec::smallvec![(1, 0)],
                },
                vec![1, 5],
                [1, 4, 0, 5],
                [0, 1, 2, 3],
            ),
            (
                Folder {
                    coders: smallvec::smallvec![copy(), copy(), copy(), bcj2()],
                    packed_indices: smallvec::smallvec![2, 6, 1, 0],
                    bind_pairs: smallvec::smallvec![(5, 0), (4, 1), (3, 2)],
                },
                vec![0, 4, 1, 5],
                [1, 5, 4, 0],
                [0, 2, 3, 1],
            ),
            (
                Folder {
                    coders: smallvec::smallvec![copy(), copy(), copy(), bcj2()],
                    packed_indices: smallvec::smallvec![0, 6, 2, 1],
                    bind_pairs: smallvec::smallvec![(3, 0), (5, 1), (4, 2)],
                },
                vec![1, 0, 4, 5],
                [1, 5, 4, 0],
                [0, 2, 3, 1],
            ),
            (
                Folder {
                    coders: smallvec::smallvec![bcj2(), copy(), copy(), copy()],
                    packed_indices: smallvec::smallvec![6, 5, 4, 3],
                    bind_pairs: smallvec::smallvec![(0, 3), (2, 1), (1, 2)],
                },
                vec![5, 0, 4, 1],
                [1, 4, 0, 5],
                [0, 1, 2, 3],
            ),
        ];
        for (folder, outputs, packed, expected) in layouts {
            let graph = folder.graph().unwrap();
            assert!(matches!(
                DecoderPlan::compile_with_working_set_limit(
                    &folder,
                    &graph,
                    5,
                    &outputs,
                    &packed,
                    Some(0),
                ),
                Err(R7zError::ResourceLimitExceeded {
                    resource: "decoder working set",
                    limit: 0,
                })
            ));
            let inputs = |bad_slot| {
                packed
                    .iter()
                    .enumerate()
                    .map(|(index, &size)| PackedInput {
                        reader: Unreadable(index),
                        size: size as usize + usize::from(bad_slot == Some(index)),
                    })
                    .collect()
            };
            for slot in 0..4 {
                let plan = DecoderPlan::compile(&folder, &graph, 5, &outputs, &packed).unwrap();
                assert!(matches!(
                    plan.bind(inputs(Some(slot))),
                    Err(R7zError::Parse)
                ));
            }
            let plan = DecoderPlan::compile(&folder, &graph, 5, &outputs, &packed).unwrap();
            let ready = plan.bind(inputs(None)).unwrap();
            let BoundTopology::Bcj2(bcj2) = ready.topology else {
                panic!("BCJ2 plan must bind BCJ2 channels");
            };
            assert_eq!(
                [
                    bcj2.main.input.get_ref().0,
                    bcj2.call.input.get_ref().0,
                    bcj2.jump.input.get_ref().0,
                    bcj2.control.input.get_ref().0
                ],
                expected
            );
        }
    }

    #[test]
    fn bcj2_working_set_includes_the_control_branch_decoder() {
        let aes = || coder(&[0x24, 6, 0xf1, 7, 1, 2, 0, 0]);
        let bcj2 = || coder(&[0x14, 3, 3, 1, 0x1b, 4, 1]);
        let folder = Folder {
            coders: smallvec::smallvec![aes(), aes(), aes(), aes(), bcj2()],
            bind_pairs: smallvec::smallvec![(4, 0), (5, 1), (6, 2), (7, 3)],
            packed_indices: smallvec::smallvec![0, 1, 2, 3],
        };
        let graph = folder.graph().unwrap();
        let outputs = [3, 1, 1, 1, 5];
        let packed = [16, 16, 16, 16];
        let one_aes = AES_CBC_WORKING_SET_BYTES + DECODER_OVERHEAD_BYTES;
        let limit = one_aes * 3 + 10;

        assert!(matches!(
            DecoderPlan::compile_with_working_set_limit(
                &folder,
                &graph,
                5,
                &outputs,
                &packed,
                Some(limit as u64),
            ),
            Err(R7zError::ResourceLimitExceeded {
                resource: "decoder working set",
                limit: actual,
            }) if actual == limit as u64
        ));
    }

    fn coder(bytes: &[u8]) -> crate::CoderInfo {
        crate::CoderInfo::parse(bytes).unwrap().1
    }

    #[test]
    fn decoders_reject_properties_they_do_not_apply() {
        let methods = [
            crate::SevenZMethod::Copy,
            crate::SevenZMethod::Bcj,
            crate::SevenZMethod::Arm,
            crate::SevenZMethod::ArmThumb,
            crate::SevenZMethod::Ia64,
            crate::SevenZMethod::Ppc,
            crate::SevenZMethod::Sparc,
            crate::SevenZMethod::Deflate,
            crate::SevenZMethod::BZip2,
            crate::SevenZMethod::Deflate64,
            crate::SevenZMethod::Swap2,
            crate::SevenZMethod::Swap4,
        ];
        for method in methods {
            let mut coder = coder(&[1, 0]);
            coder.codec_id = arrayvec::ArrayVec::from_iter(method.id().iter().copied());
            coder.properties = Some(smallvec::smallvec![0]);
            assert!(
                matches!(
                    CoderPlan::compile(&coder, OutputSize::Known(0)),
                    Err(R7zError::Decompression)
                ),
                "{} accepted ignored properties",
                method.name()
            );

            coder.properties = Some(smallvec::SmallVec::new());
            assert!(CoderPlan::compile(&coder, OutputSize::Known(0)).is_ok());
        }
    }

    #[test]
    fn bcj2_rejects_properties_before_binding_inputs() {
        let copy = || coder(&[1, 0]);
        let bcj2 = || coder(&[0x14, 3, 3, 1, 0x1b, 4, 1]);
        let mut folder = Folder {
            coders: smallvec::smallvec![copy(), bcj2()],
            packed_indices: smallvec::smallvec![0, 2, 3, 4],
            bind_pairs: smallvec::smallvec![(1, 0)],
        };
        folder.coders[1].properties = Some(smallvec::smallvec![0]);
        let graph = folder.graph().unwrap();
        assert!(matches!(
            DecoderPlan::compile(&folder, &graph, 5, &[1, 5], &[1, 4, 0, 5]),
            Err(R7zError::Decompression)
        ));
    }

    #[test]
    fn typed_codec_plans_preserve_memory_estimates() {
        let lzma2 = CoderPlan::compile(&coder(&[0x21, 0x21, 1, 0]), OutputSize::Known(0)).unwrap();
        assert_eq!(
            lzma2.working_set().unwrap().0,
            4096 + MAX_LZMA2_PROBABILITY_BYTES + DECODER_OVERHEAD_BYTES
        );
        let ppmd = CoderPlan::compile(
            &coder(&[0x23, 3, 4, 1, 5, 6, 0, 0, 16, 0]),
            OutputSize::Known(0),
        )
        .unwrap();
        assert_eq!(
            ppmd.working_set().unwrap().0,
            1024 * 1024 + DECODER_OVERHEAD_BYTES
        );
        let copy = CoderPlan::compile(&coder(&[1, 0]), OutputSize::Known(0)).unwrap();
        assert_eq!(copy.working_set().unwrap().0, 0);
    }

    #[test]
    fn aes_working_set_covers_streaming_state() {
        let aes = CoderPlan::compile(
            &coder(&[0x24, 6, 0xf1, 7, 1, 2, 0, 0]),
            OutputSize::Known(0),
        )
        .unwrap();
        assert_eq!(
            aes.working_set().unwrap().0,
            AES_CBC_WORKING_SET_BYTES + DECODER_OVERHEAD_BYTES
        );
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
        let mut budget = operation_budget();
        assert!(ready.materialize(None, &mut budget).unwrap().is_empty());
    }

    fn pair(first: crate::CoderInfo, second: crate::CoderInfo) -> Folder {
        Folder {
            coders: smallvec::smallvec![first, second],
            bind_pairs: smallvec::smallvec![(1, 0)],
            packed_indices: smallvec::smallvec![0],
        }
    }

    #[test]
    fn omitted_lzma_size_is_inferred_through_filters_in_graph_order() {
        let data = b"a chain whose LZMA stream has no end marker";
        let (properties, packed) = compress_lzma(data).unwrap();
        let mut lzma = coder(&[0x23, 3, 1, 1, 5, 0x5d, 0, 0, 16, 0]);
        lzma.properties = Some(properties.into());
        let mut folder = pair(lzma, coder(&[1, 0]));
        for reversed in [false, true] {
            if reversed {
                folder.coders.reverse();
                folder.bind_pairs = smallvec::smallvec![(0, 1)];
                folder.packed_indices = smallvec::smallvec![1];
            }
            assert_eq!(
                decompress_folder_with_password_and_sizes(
                    &folder,
                    &packed,
                    data.len() as u64,
                    &[],
                    None
                )
                .unwrap(),
                data
            );
        }
    }

    #[test]
    fn omitted_lzma_size_uses_the_end_marker_and_zero_remains_explicit() {
        let data = b"nested compression with independent end markers";
        let mut deflate =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        deflate.write_all(data).unwrap();
        let inner = deflate.finish().unwrap();
        let options = LzmaOptions::with_preset(0);
        let mut lzma = LzmaWriter::new_no_header(Vec::new(), &options, true).unwrap();
        let mut properties = vec![lzma.props()];
        properties.extend_from_slice(&options.dict_size.to_le_bytes());
        lzma.write_all(&inner).unwrap();
        let packed = lzma.finish().unwrap();
        let mut lzma_coder = coder(&[0x23, 3, 1, 1, 5, 0x5d, 0, 0, 16, 0]);
        lzma_coder.properties = Some(properties.into());
        let folder = pair(lzma_coder, coder(&[3, 4, 1, 8]));
        assert_eq!(
            decompress_folder_with_password_and_sizes(
                &folder,
                &packed,
                data.len() as u64,
                &[],
                None
            )
            .unwrap(),
            data
        );
        assert!(
            decompress_folder_with_password_and_sizes(
                &folder,
                &packed,
                data.len() as u64,
                &[0],
                None
            )
            .is_err()
        );
    }

    #[test]
    fn size_required_codecs_are_resolved_before_readers_are_opened() {
        let ppmd = || coder(&[0x23, 3, 4, 1, 5, 6, 0, 0, 16, 0]);
        let unresolved = pair(ppmd(), coder(&[0x21, 0x21, 1, 0]));
        assert!(matches!(
            prepare_folder_decoder(
                &unresolved,
                smallvec::smallvec![PackedInput {
                    reader: Unreadable(0),
                    size: 3
                }],
                7,
                &[]
            ),
            Err(R7zError::InvalidOptions("coder requires an output size"))
        ));
        let inferred = pair(ppmd(), coder(&[1, 0]));
        let ready = prepare_folder_decoder(
            &inferred,
            smallvec::smallvec![PackedInput {
                reader: Unreadable(0),
                size: 3
            }],
            7,
            &[],
        )
        .unwrap();
        let BoundTopology::Chain { steps, .. } = ready.topology else {
            panic!("expected a chain");
        };
        assert!(steps.iter().all(|step| step.output == OutputSize::Known(7)));
    }

    #[test]
    fn adapter_rejects_excess_and_conflicting_size_entries_before_reading() {
        let folder = Folder::parse(&[1, 1, 0]).unwrap().1;
        for sizes in [&[3, 3][..], &[0][..], &[2][..], &[4][..]] {
            assert!(
                prepare_folder_decoder(
                    &folder,
                    smallvec::smallvec![PackedInput {
                        reader: Unreadable(0),
                        size: 3
                    }],
                    3,
                    sizes
                )
                .is_err()
            );
        }
    }

    #[test]
    fn aes_admission_does_not_scale_with_the_preceding_coders_output() {
        let folder = pair(
            coder(&[0x21, 0x21, 1, 0]),
            coder(&[0x24, 6, 0xf1, 7, 1, 2, 0, 0]),
        );
        let graph = folder.graph().unwrap();
        let plan = DecoderPlan::compile(&folder, &graph, 0, &[4096, 0], &[16]).unwrap();
        assert_eq!(
            plan.memory.0,
            4096 + MAX_LZMA2_PROBABILITY_BYTES
                + DECODER_OVERHEAD_BYTES
                + AES_CBC_WORKING_SET_BYTES
                + DECODER_OVERHEAD_BYTES
        );
        for sizes in [&[][..], &[256 * 1024 * 1024, 0][..]] {
            assert!(
                prepare_folder_decoder(
                    &folder,
                    smallvec::smallvec![PackedInput {
                        reader: Unreadable(0),
                        size: 16
                    }],
                    0,
                    sizes
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn bcj2_rejects_inconsistent_channel_sizes_in_both_layouts() {
        let copy = || coder(&[1, 0]);
        let bcj2 = || coder(&[0x14, 3, 3, 1, 0x1b, 4, 1]);
        for (folder, sizes, packed) in [
            (
                Folder {
                    coders: smallvec::smallvec![copy(), bcj2()],
                    packed_indices: smallvec::smallvec![0, 2, 3, 4],
                    bind_pairs: smallvec::smallvec![(1, 0)],
                },
                vec![1, 6],
                [1, 4, 0, 5],
            ),
            (
                Folder {
                    coders: smallvec::smallvec![copy(), copy(), copy(), bcj2()],
                    packed_indices: smallvec::smallvec![2, 6, 1, 0],
                    bind_pairs: smallvec::smallvec![(5, 0), (4, 1), (3, 2)],
                },
                vec![0, 4, 1, 6],
                [1, 5, 4, 0],
            ),
        ] {
            let graph = folder.graph().unwrap();
            assert!(matches!(
                DecoderPlan::compile(&folder, &graph, 6, &sizes, &packed),
                Err(R7zError::Decompression)
            ));
        }
    }

    #[test]
    fn compressed_output_cannot_exceed_or_fall_short_of_its_declared_size() {
        // One uncompressed LZMA2 chunk containing "abc", followed by EOF.
        let packed = [1, 0, 2, b'a', b'b', b'c', 0];
        let folder = pair(coder(&[0x21, 0x21, 1, 0]), coder(&[1, 0]));
        for size in [0, 2, 4] {
            assert!(
                decompress_folder_with_password_and_sizes(
                    &folder,
                    &packed,
                    size,
                    &[size, size],
                    None
                )
                .is_err()
            );
        }
        assert_eq!(
            decompress_folder_with_password_and_sizes(&folder, &packed, 3, &[], None).unwrap(),
            b"abc"
        );
    }
}
