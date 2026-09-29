use std::{
    io::{self, Cursor, Seek, SeekFrom, Write},
    num::NonZeroU64,
};

use r7z::{
    Archive, ArchiveBuilder, ArchiveOptions, ArchiveWriter, Codec, EncoderThreads,
    EncryptionOptions, EntryKind, EntryMeta, PreservedArchiveEntry, PreservedEntryStream, R7zError,
    SolidMode, write_archive_with_preserved_folders,
};

const MIB: usize = 1024 * 1024;

fn options(codec: Codec) -> ArchiveOptions {
    let mut options = ArchiveOptions {
        codec,
        ..ArchiveOptions::default()
    };
    options.compression.dictionary_size = Some(MIB as u32);
    options.compression.lzma2_chunk_size = NonZeroU64::new(MIB as u64);
    options.compression.threads = EncoderThreads::Fixed(2);
    options.compression.encoder_memory_limit = Some(512 * MIB as u64);
    options
}

fn payload() -> Vec<u8> {
    (0..(3 * MIB + 17))
        .map(|index| (index % 251) as u8)
        .collect()
}

fn assert_two_files(bytes: Vec<u8>, first: &[u8], second: &[u8]) {
    let archive = Archive::from_bytes(bytes.into()).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), first);
    assert_eq!(archive.extract_to_memory(1).unwrap(), second);
}

#[test]
fn buffered_and_incremental_writers_encode_multiple_blocks_in_order() {
    let data = payload();
    let (first, second) = data.split_at(MIB + 19);
    let opts = options(Codec::Lzma2);

    let bytes = ArchiveBuilder::new()
        .options(opts.clone())
        .add_file("first.bin", first)
        .add_file("second.bin", second)
        .build()
        .unwrap();
    assert_two_files(bytes, first, second);

    let mut output = Cursor::new(Vec::new());
    let mut writer = ArchiveWriter::new(&mut output, opts).unwrap();
    writer.append("first.bin", first).unwrap();
    writer.append("second.bin", second).unwrap();
    writer.finish().unwrap();
    assert_two_files(output.into_inner(), first, second);
}

#[test]
fn staged_bcj_writer_preserves_bytes_across_parallel_blocks() {
    let mut data = payload();
    data[MIB - 2..MIB + 3].copy_from_slice(&[0x90, 0xE8, 0, 0, 0]);
    let entries = vec![PreservedArchiveEntry {
        name: "program.bin".to_string(),
        raw_name: None,
        kind: EntryKind::File,
        meta: EntryMeta::default(),
        stream: PreservedEntryStream::Data(data.clone()),
    }];
    let output = write_archive_with_preserved_folders(
        Cursor::new(Vec::new()),
        entries,
        Vec::new(),
        &options(Codec::Lzma2Bcj),
    )
    .unwrap();
    let archive = Archive::from_bytes(output.into_inner().into()).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), data);
}

#[test]
fn encrypted_buffered_archive_round_trips_with_parallel_encoder() {
    let data = payload();
    let mut opts = options(Codec::Lzma2);
    opts.encryption = Some(EncryptionOptions::default_for_password("parallel-secret"));
    let bytes = ArchiveBuilder::new()
        .options(opts)
        .add_file("secret.bin", &data)
        .build()
        .unwrap();
    let archive = Archive::from_bytes_with_password(bytes.into(), Some("parallel-secret")).unwrap();
    assert_eq!(
        archive
            .extract_to_memory_with_password(0, Some("parallel-secret"))
            .unwrap(),
        data
    );
}

#[test]
fn explicit_encoder_allowance_rejects_work_before_encoding() {
    let mut opts = options(Codec::Lzma2);
    opts.compression.encoder_memory_limit = Some(1024);
    let error = ArchiveBuilder::new()
        .options(opts)
        .add_file("file.bin", &payload())
        .build()
        .unwrap_err();
    assert!(matches!(error, R7zError::LimitExceeded("encoder memory")));
}

#[test]
fn empty_file_and_non_solid_folders_round_trip() {
    let data = payload();
    let (first, second) = data.split_at(MIB + 19);
    let mut opts = options(Codec::Lzma2);
    opts.compression.solid = SolidMode::NonSolid;
    let bytes = ArchiveBuilder::new()
        .options(opts)
        .add_file("empty.bin", &[])
        .add_file("first.bin", first)
        .add_file("second.bin", second)
        .build()
        .unwrap();
    let archive = Archive::from_bytes(bytes.into()).unwrap();
    assert_eq!(archive.extract_to_memory(0).unwrap(), b"");
    assert_eq!(archive.extract_to_memory(1).unwrap(), first);
    assert_eq!(archive.extract_to_memory(2).unwrap(), second);
}

struct FailingOutput(Cursor<Vec<u8>>);

impl Write for FailingOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.0.position().saturating_add(buf.len() as u64) > 64 {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "output closed"));
        }
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Seek for FailingOutput {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

#[test]
fn parallel_writer_propagates_output_error_and_joins_workers() {
    let result = (|| {
        let mut writer = ArchiveWriter::new(
            FailingOutput(Cursor::new(Vec::new())),
            options(Codec::Lzma2),
        )?;
        writer.append("file.bin", Cursor::new(payload()))?;
        writer.finish().map(|_| ())
    })();
    assert!(
        matches!(result, Err(R7zError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe)
    );
}
