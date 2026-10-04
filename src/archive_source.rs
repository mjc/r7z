use crate::byte_range::ArchiveSourceRange;
use crate::resources::OperationBudget;
use crate::{R7zError, SignatureHeader, codec};
use bytes::Bytes;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub(crate) const SEVEN_Z_MAGIC: &[u8; 6] = b"7z\xbc\xaf'\x1c";
const SIGNATURE_SCAN_CHUNK: usize = 64 * 1024;

trait ReadSeek: Read + Seek {}

impl<T: Read + Seek> ReadSeek for T {}

enum ArchiveSourceKind {
    Bytes(Bytes),
    File {
        file: PositionedFile,
        len: u64,
    },
    Seekable {
        reader: Mutex<Box<dyn ReadSeek + Send>>,
        len: u64,
    },
    Volumes {
        readers: Vec<VolumeReader>,
        len: u64,
    },
}

pub(crate) struct ArchiveSource {
    kind: ArchiveSourceKind,
}

impl ArchiveSource {
    pub(crate) fn from_bytes(bytes: Bytes) -> Self {
        Self {
            kind: ArchiveSourceKind::Bytes(bytes),
        }
    }

    pub(crate) fn from_reader<R>(mut reader: R) -> Result<Self, R7zError>
    where
        R: Read + Seek + Send + 'static,
    {
        let len = reader.seek(SeekFrom::End(0)).map_err(R7zError::Io)?;
        Ok(Self {
            kind: ArchiveSourceKind::Seekable {
                reader: Mutex::new(Box::new(reader)),
                len,
            },
        })
    }

    pub(crate) fn from_file(path: &Path, budget: &mut OperationBudget) -> Result<Self, R7zError> {
        if let Some(source) = Self::from_split_first_volume(path, budget)? {
            return Ok(source);
        }

        budget.charge_open_volume()?;
        let file = PositionedFile::open(path)?;
        let len = file.len()?;
        Ok(Self {
            kind: ArchiveSourceKind::File { file, len },
        })
    }

    pub(crate) fn from_split_first_volume(
        path: &Path,
        budget: &mut OperationBudget,
    ) -> Result<Option<Self>, R7zError> {
        if !is_split_first_volume(path) {
            return Ok(None);
        }

        let mut readers = Vec::new();
        let mut len = 0u64;
        for idx in 1.. {
            let path = split_volume_path(path, idx);
            if !path.exists() {
                break;
            }
            budget.charge_open_volume()?;
            let file = PositionedFile::open(&path)?;
            let volume_len = file.len()?;
            let start = len;
            len = checked_add_u64(len, volume_len)?;
            readers.push(VolumeReader {
                file,
                start,
                end: len,
            });
        }

        if readers.len() > 1 {
            Ok(Some(Self {
                kind: ArchiveSourceKind::Volumes { readers, len },
            }))
        } else {
            budget.release_open_volume();
            Ok(None)
        }
    }

    pub(crate) fn len(&self) -> Result<u64, R7zError> {
        match &self.kind {
            ArchiveSourceKind::Bytes(bytes) => {
                u64::try_from(bytes.len()).map_err(|_| R7zError::Parse)
            }
            ArchiveSourceKind::File { len, .. }
            | ArchiveSourceKind::Seekable { len, .. }
            | ArchiveSourceKind::Volumes { len, .. } => Ok(*len),
        }
    }

    pub(crate) fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> Result<(), R7zError> {
        if dst.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(u64::try_from(dst.len()).map_err(|_| R7zError::Parse)?)
            .ok_or(R7zError::Parse)?;
        if end > self.len()? {
            return Err(R7zError::Parse);
        }
        match &self.kind {
            ArchiveSourceKind::Bytes(bytes) => {
                let start = usize::try_from(offset).map_err(|_| R7zError::Parse)?;
                let end = usize::try_from(end).map_err(|_| R7zError::Parse)?;
                dst.copy_from_slice(bytes.get(start..end).ok_or(R7zError::Parse)?);
                Ok(())
            }
            ArchiveSourceKind::File { file, .. } => {
                file.read_exact_at(offset, dst).map_err(R7zError::Io)
            }
            ArchiveSourceKind::Seekable { reader, .. } => {
                let mut reader = reader.lock().map_err(|_| R7zError::Parse)?;
                reader.seek(SeekFrom::Start(offset))?;
                reader.read_exact(dst)?;
                Ok(())
            }
            ArchiveSourceKind::Volumes { readers, .. } => {
                let mut logical_offset = offset;
                let mut remaining = dst;
                while !remaining.is_empty() {
                    let volume = readers
                        .iter()
                        .find(|volume| {
                            logical_offset >= volume.start && logical_offset < volume.end
                        })
                        .ok_or(R7zError::Parse)?;
                    let volume_offset = logical_offset - volume.start;
                    let available = volume.end - logical_offset;
                    let n = usize::try_from(available.min(remaining.len() as u64))
                        .map_err(|_| R7zError::Parse)?;
                    volume
                        .file
                        .read_exact_at(volume_offset, &mut remaining[..n])?;
                    logical_offset = logical_offset
                        .checked_add(n as u64)
                        .ok_or(R7zError::Parse)?;
                    remaining = &mut remaining[n..];
                }
                Ok(())
            }
        }
    }

    pub(crate) fn read_range_to_vec(
        &self,
        range: ArchiveSourceRange,
        limit: u64,
    ) -> Result<Vec<u8>, R7zError> {
        let len = range.len();
        if len > limit {
            return Err(R7zError::LimitExceeded("metadata"));
        }
        let len = usize::try_from(len).map_err(|_| R7zError::Parse)?;
        let mut out = vec![0u8; len];
        self.read_exact_at(range.start(), &mut out)?;
        Ok(out)
    }

    pub(crate) fn range_reader(
        &self,
        range: ArchiveSourceRange,
    ) -> Result<ArchiveRangeReader<'_>, R7zError> {
        if range.end() > self.len()? {
            return Err(R7zError::Parse);
        }
        Ok(ArchiveRangeReader {
            source: self,
            pos: range.start(),
            end: range.end(),
        })
    }

    pub(crate) fn packed_input(
        &self,
        range: ArchiveSourceRange,
    ) -> Result<codec::PackedInput<ArchiveRangeReader<'_>>, R7zError> {
        let size = usize::try_from(range.len()).map_err(|_| R7zError::Parse)?;
        Ok(codec::PackedInput {
            reader: self.range_reader(range)?,
            size,
        })
    }

    pub(crate) fn find_signature(&self, limit: u64) -> Result<(u64, SignatureHeader), R7zError> {
        let source_len = self.len()?;
        let scan_len = source_len.min(limit);
        let mut offset = 0u64;
        let mut carry = Vec::new();
        let mut saw_bad_signature = false;

        while offset < scan_len {
            let remaining = scan_len - offset;
            let chunk_len = usize::try_from(remaining.min(SIGNATURE_SCAN_CHUNK as u64))
                .map_err(|_| R7zError::Parse)?;
            let mut chunk = vec![0u8; chunk_len];
            self.read_exact_at(offset, &mut chunk)?;

            let carry_len = carry.len();
            carry.extend_from_slice(&chunk);
            let search_start = carry_len.saturating_sub(SEVEN_Z_MAGIC.len() - 1);
            let base = offset
                .checked_sub(carry_len as u64)
                .ok_or(R7zError::Parse)?;

            for pos in find_magic_offsets(&carry[search_start..]) {
                let pos = search_start.checked_add(pos).ok_or(R7zError::Parse)?;
                let candidate = base.checked_add(pos as u64).ok_or(R7zError::Parse)?;
                match self.signature_at(candidate)? {
                    SignatureCandidate::Valid(signature) => return Ok((candidate, signature)),
                    SignatureCandidate::BadCrc => saw_bad_signature = true,
                    SignatureCandidate::Incomplete => {}
                }
            }

            if carry.len() >= SEVEN_Z_MAGIC.len() - 1 {
                carry = carry[carry.len() - (SEVEN_Z_MAGIC.len() - 1)..].to_vec();
            }
            offset = offset
                .checked_add(chunk_len as u64)
                .ok_or(R7zError::Parse)?;
        }

        if saw_bad_signature {
            Err(R7zError::Crc)
        } else if source_len > limit {
            Err(R7zError::ResourceLimitExceeded {
                resource: "signature scan",
                limit,
            })
        } else {
            Err(R7zError::Parse)
        }
    }

    fn signature_at(&self, offset: u64) -> Result<SignatureCandidate, R7zError> {
        if offset.checked_add(32).ok_or(R7zError::Parse)? > self.len()? {
            return Ok(SignatureCandidate::Incomplete);
        }
        let mut signature_bytes = [0u8; 32];
        self.read_exact_at(offset, &mut signature_bytes)?;
        let (_, signature) =
            SignatureHeader::parse(&signature_bytes).map_err(|_| R7zError::Parse)?;
        if signature.signature != *SEVEN_Z_MAGIC {
            return Ok(SignatureCandidate::Incomplete);
        }
        match signature.validate_start_header_crc() {
            Ok(()) => Ok(SignatureCandidate::Valid(signature)),
            Err(R7zError::Crc) => Ok(SignatureCandidate::BadCrc),
            Err(err) => Err(err),
        }
    }
}

enum SignatureCandidate {
    Valid(SignatureHeader),
    BadCrc,
    Incomplete,
}

struct VolumeReader {
    file: PositionedFile,
    start: u64,
    end: u64,
}

#[cfg(any(unix, windows))]
struct PositionedFile(std::fs::File);

#[cfg(not(any(unix, windows)))]
struct PositionedFile(Mutex<std::fs::File>);

impl PositionedFile {
    fn open(path: &Path) -> Result<Self, R7zError> {
        let file = std::fs::File::open(path)?;
        #[cfg(any(unix, windows))]
        let file = Self(file);
        #[cfg(not(any(unix, windows)))]
        let file = Self(Mutex::new(file));
        Ok(file)
    }

    pub(crate) fn len(&self) -> Result<u64, R7zError> {
        #[cfg(any(unix, windows))]
        let file = &self.0;
        #[cfg(not(any(unix, windows)))]
        let file = self.0.lock().map_err(|_| R7zError::Parse)?;
        Ok(file.metadata()?.len())
    }

    pub(crate) fn read_exact_at(&self, offset: u64, dst: &mut [u8]) -> std::io::Result<()> {
        #[cfg(not(any(unix, windows)))]
        {
            let mut file = self
                .0
                .lock()
                .map_err(|_| std::io::Error::other("file lock poisoned"))?;
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(dst)
        }

        #[cfg(any(unix, windows))]
        {
            #[cfg(unix)]
            use std::os::unix::fs::FileExt;
            #[cfg(windows)]
            use std::os::windows::fs::FileExt;

            let mut offset = offset;
            let mut dst = dst;
            while !dst.is_empty() {
                let read = loop {
                    #[cfg(unix)]
                    let result = self.0.read_at(dst, offset);
                    #[cfg(windows)]
                    let result = self.0.seek_read(dst, offset);

                    match result {
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        result => break result?,
                    }
                };
                if read == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                offset = offset
                    .checked_add(read as u64)
                    .ok_or_else(|| std::io::Error::other("file offset overflow"))?;
                dst = &mut dst[read..];
            }
            Ok(())
        }
    }
}

pub(crate) struct ArchiveRangeReader<'a> {
    source: &'a ArchiveSource,
    pos: u64,
    end: u64,
}

impl Read for ArchiveRangeReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.end || buf.is_empty() {
            return Ok(0);
        }
        let remaining = self.end - self.pos;
        let n = usize::try_from(remaining.min(buf.len() as u64))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "range too large"))?;
        self.source
            .read_exact_at(self.pos, &mut buf[..n])
            .map_err(std::io::Error::other)?;
        self.pos += n as u64;
        Ok(n)
    }
}

fn checked_add_u64(lhs: u64, rhs: u64) -> Result<u64, R7zError> {
    lhs.checked_add(rhs).ok_or(R7zError::Parse)
}

pub(crate) fn find_magic_offsets(haystack: &[u8]) -> impl Iterator<Item = usize> + '_ {
    haystack
        .windows(SEVEN_Z_MAGIC.len())
        .enumerate()
        .filter_map(|(idx, bytes)| (bytes == SEVEN_Z_MAGIC).then_some(idx))
}

fn is_split_first_volume(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "001")
}

fn split_volume_path(first_volume: &Path, idx: u64) -> PathBuf {
    first_volume.with_extension(format!("{idx:03}"))
}
