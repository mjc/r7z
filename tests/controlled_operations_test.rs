use r7z::{
    Archive, ArchiveBuilder, ArchiveEntryIndex, ArchiveOptions, ArchiveReadConfig, ArchiveWriter,
    Codec, OperationControl, R7zError, ReadVerification,
};
use std::{
    io::{self, Cursor, Write},
    ops::ControlFlow,
};

fn cancelling_control() -> OperationControl {
    OperationControl::with_progress(|_| ControlFlow::Break(()))
}

fn controlled_options(control: OperationControl) -> ArchiveOptions {
    let mut options = ArchiveOptions {
        codec: Codec::Copy,
        ..ArchiveOptions::default()
    };
    options.streaming.control = Some(control);
    options
}

fn copy_archive() -> Archive {
    Archive::from_bytes(
        ArchiveBuilder::new()
            .compression(Codec::Copy)
            .add_file("first", &vec![0; 128 * 1024])
            .add_file("last", b"last")
            .build()
            .unwrap()
            .into(),
    )
    .unwrap()
}

#[test]
fn cancelled_read_is_distinct_from_corruption() {
    let archive = copy_archive();
    let control = cancelling_control();
    let result = archive.extract_to_writer_with_options(
        ArchiveEntryIndex::new(0),
        &mut io::sink(),
        ArchiveReadConfig::default().with_control(&control),
    );
    assert!(matches!(result, Err(R7zError::Cancelled)));
}

#[test]
fn cancellation_stops_automatic_drain_after_an_early_consumer() {
    let archive = copy_archive();
    let control = cancelling_control();
    let mut session = archive
        .read_session_with_options(ArchiveReadConfig::default().with_control(&control))
        .unwrap();
    assert!(matches!(
        session.read_entry(ArchiveEntryIndex::new(0), |reader| {
            reader.read_exact(&mut [0])?;
            Ok(())
        }),
        Err(R7zError::Cancelled)
    ));
    assert!(matches!(session.finish(), Err(R7zError::Cancelled)));
}

#[test]
fn successful_early_consumers_are_drained_and_verification_scope_is_explicit() {
    let archive = copy_archive();
    let mut session = archive.read_session(None).unwrap();
    session
        .read_entry(ArchiveEntryIndex::new(0), |reader| {
            reader.read_exact(&mut [0])?;
            Ok(())
        })
        .unwrap();
    assert_eq!(session.finish().unwrap(), ReadVerification::SelectedEntries);
    let mut session = archive.read_session(None).unwrap();
    session
        .read_entry(ArchiveEntryIndex::new(0), |_| Ok(()))
        .unwrap();
    session
        .read_entry(ArchiveEntryIndex::new(1), |_| Ok(()))
        .unwrap();
    assert_eq!(session.finish().unwrap(), ReadVerification::CompleteFolders);
}

struct FailedOutput;
impl Write for FailedOutput {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "output closed"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn output_errors_keep_their_cause_and_leave_verification_incomplete() {
    let archive = copy_archive();
    let mut session = archive.read_session(None).unwrap();
    assert!(
        matches!(session.extract_to_writer(ArchiveEntryIndex::new(0), &mut FailedOutput),
        Err(R7zError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe && error.to_string() == "output closed")
    );
    session
        .read_entry(ArchiveEntryIndex::new(1), |_| Ok(()))
        .unwrap();
    assert_eq!(session.finish().unwrap(), ReadVerification::Incomplete);
}

#[test]
fn io_errors_expose_the_original_source() {
    let error = R7zError::from(io::Error::new(io::ErrorKind::BrokenPipe, "output closed"));
    let source = std::error::Error::source(&error).unwrap();
    assert_eq!(
        source.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::BrokenPipe
    );
}

struct CancelOnPackedWrite {
    bytes: Cursor<Vec<u8>>,
    control: OperationControl,
}

impl Write for CancelOnPackedWrite {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let packed_data = self.bytes.position() >= 32;
        let written = self.bytes.write(data)?;
        if packed_data {
            self.control.cancel();
        }
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Seek for CancelOnPackedWrite {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        self.bytes.seek(position)
    }
}

#[test]
fn preserved_multithreaded_encoding_reports_worker_cancellation() {
    let control = OperationControl::new();
    let mut options = controlled_options(control.clone());
    options.codec = Codec::Lzma2;
    options.compression.threads = r7z::EncoderThreads::Fixed(2);
    options.compression.dictionary_size = Some(4096);
    options.compression.lzma2_chunk_size = std::num::NonZeroU64::new(4096);
    let entry = r7z::update::v1::PreservedArchiveEntry {
        name: "file".into(),
        raw_name: None,
        kind: r7z::EntryKind::File,
        meta: r7z::EntryMeta::default(),
        stream: r7z::update::v1::PreservedEntryStream::Data(vec![0; 128 * 1024]),
    };
    let output = CancelOnPackedWrite {
        bytes: Cursor::new(Vec::new()),
        control,
    };
    let result = r7z::update::v1::write_archive_with_preserved_folders(
        output,
        vec![entry],
        Vec::new(),
        &options,
    );
    assert!(matches!(result, Err(R7zError::Cancelled)));
}

#[test]
fn writer_cancellation_stops_input_and_poisons_the_writer() {
    let control = cancelling_control();
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new()), controlled_options(control))
        .unwrap()
        .start();
    let mut input = Cursor::new(vec![0; 128 * 1024]);
    assert!(matches!(
        writer.append("file", &mut input),
        Err(R7zError::Cancelled)
    ));
    assert_eq!(input.position(), 64 * 1024);
    assert!(writer.append("next", io::empty()).is_err());
    assert!(writer.finish().is_err());
}

#[test]
fn precancelled_writer_does_not_touch_the_input_or_output() {
    let control = OperationControl::new();
    control.cancel();
    let mut output = Cursor::new(b"original".to_vec());
    let mut input = Cursor::new(b"input".to_vec());
    let mut writer = ArchiveWriter::new(&mut output, controlled_options(control))
        .unwrap()
        .start();
    assert!(matches!(
        writer.append("file", &mut input),
        Err(R7zError::Cancelled)
    ));
    drop(writer);
    assert_eq!(input.position(), 0);
    assert_eq!(output.into_inner(), b"original");
}

#[test]
fn raw_folder_copy_can_be_cancelled() {
    use r7z::update::v1::{
        FolderIndex, PreservedArchiveEntry, PreservedEntryStream, write_archive_update,
    };
    let archive = copy_archive();
    let folder = archive.raw_folder(FolderIndex::new(0)).unwrap();
    let listing = archive.listing(None).unwrap();
    let entries = archive
        .entries()
        .zip(listing.entries)
        .map(|(entry, info)| PreservedArchiveEntry {
            name: entry.name,
            raw_name: entry.raw_name,
            kind: r7z::EntryKind::File,
            meta: r7z::EntryMeta::default(),
            stream: PreservedEntryStream::Raw {
                folder: folder.handle(),
                source_entry: entry.index,
                size: info.size.unwrap(),
                crc: info.crc,
            },
        })
        .collect();
    let result = write_archive_update(
        &archive,
        Cursor::new(Vec::new()),
        entries,
        vec![folder],
        &controlled_options(cancelling_control()),
    );
    assert!(matches!(result, Err(R7zError::Cancelled)));
}

#[test]
fn buffered_and_preserved_entry_writes_can_be_cancelled() {
    let data = vec![0; 128 * 1024];
    assert!(matches!(
        ArchiveBuilder::new()
            .options(controlled_options(cancelling_control()))
            .add_file("file", &data)
            .build(),
        Err(R7zError::Cancelled)
    ));
    let entry = r7z::update::v1::PreservedArchiveEntry {
        name: "file".into(),
        raw_name: None,
        kind: r7z::EntryKind::File,
        meta: r7z::EntryMeta::default(),
        stream: r7z::update::v1::PreservedEntryStream::Data(data),
    };
    assert!(matches!(
        r7z::update::v1::write_archive_with_preserved_folders(
            Cursor::new(Vec::new()),
            vec![entry],
            Vec::new(),
            &controlled_options(cancelling_control())
        ),
        Err(R7zError::Cancelled)
    ));
}

#[test]
fn writer_debug_redacts_passwords() {
    let options = ArchiveOptions {
        encryption: Some(r7z::EncryptionOptions::default_for_password(
            "private password",
        )),
        ..ArchiveOptions::default()
    };
    let debug = format!("{options:?}");
    assert!(!debug.contains("private password"));
    assert!(debug.contains("<redacted>"));
}

struct CancelledErrorOutput;
impl Write for CancelledErrorOutput {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other(R7zError::Cancelled))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn an_output_error_containing_cancelled_stays_an_output_error() {
    let archive = copy_archive();
    assert!(
        matches!(archive.extract_to_writer(ArchiveEntryIndex::new(0), &mut CancelledErrorOutput),
        Err(R7zError::Io(error)) if error.get_ref().unwrap().is::<R7zError>())
    );
}

#[test]
fn precancelled_updates_leave_output_untouched() {
    let control = OperationControl::new();
    control.cancel();
    let mut output = Cursor::new(b"original".to_vec());
    let result = r7z::update::v1::write_archive_with_preserved_folders(
        &mut output,
        Vec::new(),
        Vec::new(),
        &controlled_options(control),
    );
    assert!(matches!(result, Err(R7zError::Cancelled)));
    assert_eq!(output.into_inner(), b"original");
}

#[test]
fn final_spool_copy_and_volume_output_can_be_cancelled() {
    let control = OperationControl::with_progress(|progress| match progress.phase {
        r7z::OperationPhase::CopyOutput => ControlFlow::Break(()),
        r7z::OperationPhase::Read | r7z::OperationPhase::Write => ControlFlow::Continue(()),
    });
    let result = r7z::build_streaming_to_writer(
        [("file".into(), Cursor::new(vec![0; 128 * 1024]))],
        Vec::new(),
        controlled_options(control),
    );
    assert!(matches!(result, Err(R7zError::Cancelled)));
    let root = tempfile::tempdir().unwrap();
    let control = OperationControl::with_progress(|progress| match progress.phase {
        r7z::OperationPhase::CopyOutput => ControlFlow::Break(()),
        r7z::OperationPhase::Read | r7z::OperationPhase::Write => ControlFlow::Continue(()),
    });
    let result = r7z::build_streaming_volumes(
        [("file".into(), Cursor::new(vec![0; 128 * 1024]))],
        root.path().join("archive.7z"),
        controlled_options(control),
        r7z::VolumeOptions {
            sizes: vec![std::num::NonZeroU64::new(256 * 1024).unwrap()],
        },
    );
    assert!(matches!(result, Err(R7zError::Cancelled)));
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    assert!(
        std::fs::metadata(root.path().join("archive.7z.001"))
            .unwrap()
            .len()
            < 128 * 1024
    );
}

struct CancelOnFlush<'a> {
    bytes: Cursor<Vec<u8>>,
    control: &'a OperationControl,
}
impl Write for CancelOnFlush<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.bytes.write(data)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.control.cancel();
        Ok(())
    }
}
impl io::Seek for CancelOnFlush<'_> {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        self.bytes.seek(position)
    }
}

#[test]
fn metadata_only_finish_observes_cancellation_during_flush() {
    let control = OperationControl::new();
    let out = CancelOnFlush {
        bytes: Cursor::new(Vec::new()),
        control: &control,
    };
    let writer = ArchiveWriter::new(out, controlled_options(control.clone()))
        .unwrap()
        .start();
    assert!(matches!(writer.finish(), Err(R7zError::Cancelled)));
}

#[test]
fn precancelled_new_folder_leaves_output_untouched() {
    let control = OperationControl::new();
    control.cancel();
    let mut output = Cursor::new(b"original".to_vec());
    let mut writer = ArchiveWriter::new(&mut output, controlled_options(control))
        .unwrap()
        .start();
    assert!(matches!(writer.new_folder(), Err(R7zError::Cancelled)));
    assert!(writer.new_folder().is_err());
    assert!(writer.finish().is_err());
    assert_eq!(output.into_inner(), b"original");
}

#[test]
fn new_folder_observes_cancellation_for_each_serial_codec() {
    for codec in [
        Codec::Copy,
        Codec::Lzma,
        Codec::Lzma2,
        Codec::Ppmd,
        Codec::Lzma2Bcj,
    ] {
        let control = OperationControl::new();
        let mut options = controlled_options(control.clone());
        options.codec = codec;
        options.compression.threads = r7z::EncoderThreads::Single;
        let mut writer = ArchiveWriter::new(Cursor::new(Vec::new()), options)
            .unwrap()
            .start();
        writer.append("file", Cursor::new(b"small input")).unwrap();
        control.cancel();
        assert!(
            matches!(writer.new_folder(), Err(R7zError::Cancelled)),
            "{codec:?}"
        );
        let mut next = Cursor::new(b"next input");
        assert!(writer.append("next", &mut next).is_err());
        assert_eq!(next.position(), 0);
        assert!(writer.finish().is_err());
    }
}

#[test]
fn new_folder_observes_cancellation_during_encoder_completion() {
    let control = OperationControl::new();
    let mut options = controlled_options(control.clone());
    options.codec = Codec::Lzma2;
    options.compression.threads = r7z::EncoderThreads::Single;
    let output = CancelOnPackedWrite {
        bytes: Cursor::new(Vec::new()),
        control: control.clone(),
    };
    let mut writer = ArchiveWriter::new(output, options).unwrap().start();
    writer.append("file", Cursor::new(b"small input")).unwrap();
    assert!(!control.is_cancelled());
    assert!(matches!(writer.new_folder(), Err(R7zError::Cancelled)));
    assert!(control.is_cancelled());
    assert!(writer.new_folder().is_err());
    assert!(writer.finish().is_err());
}
