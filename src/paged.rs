/*
This module owns a regular-file handle and reads small windows at u64 offsets.
The handle keeps the opened source stable when its pathname changes.
Metadata checks reject detected source changes before or after each read.
L02.2 will connect this component to the viewer file lifecycle.
*/
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

/*
Each read uses at most 64 KiB of owned memory.
O_NONBLOCK lets open return before a FIFO supplies a writer.
The metadata check then rejects every nonregular source.
*/
pub(crate) const MAX_READ_BYTES: usize = 64 * 1024;
const O_NONBLOCK: i32 = 0o4000;

/*
The source stamp records length and nanosecond Linux change times.
The modification time identifies data updates.
The change time also identifies metadata updates and restored modification times.
These checks cannot exclude every concurrent writer on Linux.
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceStamp {
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl SourceStamp {
    /*
    This conversion captures one metadata sample from the owned descriptor.
    Later reads compare a new sample with these exact fields.
    */
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            len: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }

    /*
    This check gives length changes specific errors.
    A time change reports a general external source change.
    The caller must reopen the source before another read.
    */
    fn validate(self, current: Self) -> io::Result<()> {
        if current.len < self.len {
            return Err(io::Error::other(
                "The source shrank outside the viewer. Reopen the source.",
            ));
        }
        if current.len > self.len {
            return Err(io::Error::other(
                "The source grew outside the viewer. Reopen the source.",
            ));
        }
        if current.modified_seconds != self.modified_seconds
            || current.modified_nanoseconds != self.modified_nanoseconds
            || current.changed_seconds != self.changed_seconds
            || current.changed_nanoseconds != self.changed_nanoseconds
        {
            return Err(io::Error::other(
                "The source changed outside the viewer. Reopen the source.",
            ));
        }
        Ok(())
    }
}

/*
A read window owns its bytes independently from the source and later windows.
The start field keeps the u64 source position with the bounded byte buffer.
*/
#[derive(Debug)]
pub(crate) struct ReadWindow {
    pub(crate) start: u64,
    pub(crate) bytes: Box<[u8]>,
}

/*
PagedFile owns one read-only descriptor and the metadata from open time.
The component stores no display text or pathname conversion.
*/
pub(crate) struct PagedFile {
    file: File,
    stamp: SourceStamp,
}

impl PagedFile {
    /*
    Open receives a native Path and passes the path directly to Linux.
    O_NONBLOCK prevents a nonregular FIFO from delaying source validation.
    A successful result owns one regular-file descriptor and one source stamp.
    */
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "The source is not a regular file.",
            ));
        }
        Ok(Self {
            file,
            stamp: SourceStamp::from_metadata(&metadata),
        })
    }

    /*
    Length reports the captured length of the opened source.
    The next read validates this length before it accesses bytes.
    */
    pub(crate) fn len(&self) -> u64 {
        self.stamp.len
    }

    /*
    Validation reads metadata from the owned descriptor.
    Pathname replacement does not redirect the descriptor to another source.
    L02.2 will apply this behavior to viewer reopen and file-switch actions.
    */
    fn validate(&self) -> io::Result<()> {
        self.stamp
            .validate(SourceStamp::from_metadata(&self.file.metadata()?))
    }

    /*
    This read rejects invalid limits and offsets before memory allocation.
    A valid request is clipped at EOF and receives one fallibly allocated buffer.
    The 64 KiB cap makes the clipped length exact in u64 and usize.
    Positioned input does not change the shared file offset.
    The final validation prevents publication of a detected stale window.
    */
    pub(crate) fn read_window(&self, start: u64, len: usize) -> io::Result<ReadWindow> {
        if len > MAX_READ_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "A read window cannot exceed 64 KiB.",
            ));
        }

        self.validate()?;
        let available = self.stamp.len.checked_sub(start).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "The read offset is past the file end.",
            )
        })?;
        let allocation_len = available.min(len as u64) as usize;

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(allocation_len)
            .map_err(|_| io::Error::other("Cannot allocate the read window."))?;
        bytes.resize(allocation_len, 0);
        self.file.read_exact_at(&mut bytes, start)?;
        self.validate()?;

        Ok(ReadWindow {
            start,
            bytes: bytes.into_boxed_slice(),
        })
    }
}

#[cfg(test)]
mod tests {
    /*
    These tests exercise the component through disposable regular files.
    Sparse fixtures cover high u64 positions without large memory use.
    Native-path and FIFO fixtures cover Linux path and source boundaries.
    */
    use super::{MAX_READ_BYTES, PagedFile};
    use std::ffi::CString;
    use std::fs::{self, File, FileTimes, OpenOptions};
    use std::io;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::FileExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, UNIX_EPOCH};

    /*
    The C function creates a FIFO without an added Cargo dependency.
    The production O_NONBLOCK open must let the related test finish immediately.
    */
    unsafe extern "C" {
        fn mkfifo(pathname: *const std::ffi::c_char, mode: u32) -> std::ffi::c_int;
    }

    /*
    Each fixture selects a process-local unique temporary directory.
    Drop removes all sparse files, native pathnames, and FIFOs in that directory.
    */
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        path: PathBuf,
    }

    impl Fixture {
        fn new(label: &str) -> io::Result<Self> {
            let base = std::env::temp_dir();
            loop {
                let number = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!(
                    "hview-paged-{label}-{}-{number}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Ok(Self { path }),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
        }

        fn file(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /*
    This helper creates a sparse file and writes small markers at selected offsets.
    The resulting file exercises high positions while keeping memory and storage bounded.
    */
    fn sparse_file(path: &Path, len: u64, markers: &[(u64, &[u8])]) -> io::Result<()> {
        let file = OpenOptions::new().create_new(true).write(true).open(path)?;
        file.set_len(len)?;
        for (offset, bytes) in markers {
            file.write_all_at(bytes, *offset)?;
        }
        file.sync_all()
    }

    /*
    These checks establish empty-file behavior and all preallocation rejections.
    Zero-length reads are valid only at or before EOF.
    */
    #[test]
    fn empty_files_and_invalid_ranges_are_bounded() -> io::Result<()> {
        let fixture = Fixture::new("empty")?;
        let path = fixture.file("empty.bin");
        File::create(&path)?;
        let source = PagedFile::open(&path)?;

        assert_eq!(source.len(), 0);
        let at_eof = source.read_window(0, MAX_READ_BYTES)?;
        assert_eq!(at_eof.start, 0);
        assert!(at_eof.bytes.is_empty());
        assert_eq!(
            source.read_window(1, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            source.read_window(u64::MAX, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            source
                .read_window(0, MAX_READ_BYTES + 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            source.read_window(0, usize::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        Ok(())
    }

    /*
    These reads cover a complete window, a window boundary, a clipped tail, and exact EOF.
    The expected slices also check ordinary byte data.
    */
    #[test]
    fn ordinary_windows_clip_only_at_eof() -> io::Result<()> {
        let fixture = Fixture::new("ordinary")?;
        let path = fixture.file("ordinary.bin");
        let bytes: Vec<u8> = (0..(MAX_READ_BYTES * 2 + 37))
            .map(|index| (index % 251) as u8)
            .collect();
        fs::write(&path, &bytes)?;
        let source = PagedFile::open(&path)?;

        let complete = source.read_window(0, MAX_READ_BYTES)?;
        assert_eq!(&*complete.bytes, &bytes[..MAX_READ_BYTES]);
        let crossing = source.read_window((MAX_READ_BYTES - 8) as u64, 24)?;
        assert_eq!(
            &*crossing.bytes,
            &bytes[MAX_READ_BYTES - 8..MAX_READ_BYTES + 16]
        );
        let tail_start = bytes.len() - 5;
        let tail = source.read_window(tail_start as u64, MAX_READ_BYTES)?;
        assert_eq!(&*tail.bytes, &bytes[tail_start..]);
        let at_eof = source.read_window(bytes.len() as u64, 12)?;
        assert!(at_eof.bytes.is_empty());
        assert_eq!(
            source
                .read_window(bytes.len() as u64 + 1, 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        Ok(())
    }

    /*
    Each returned Box owns its data after later reads and source closure.
    This check prevents a shared scratch buffer from replacing owned windows.
    */
    #[test]
    fn retained_windows_have_independent_ownership() -> io::Result<()> {
        let fixture = Fixture::new("ownership")?;
        let path = fixture.file("source.bin");
        fs::write(&path, b"first-second-third")?;
        let source = PagedFile::open(&path)?;

        let first = source.read_window(0, 5)?;
        let second = source.read_window(6, 6)?;
        let _later = source.read_window(13, 5)?;
        drop(source);

        assert_eq!(&*first.bytes, b"first");
        assert_eq!(&*second.bytes, b"second");
        Ok(())
    }

    /*
    Sparse files verify marker reads above the buffered-file threshold and above 4 GiB.
    Boundary and final markers confirm the first, middle, high, and last positions.
    */
    #[test]
    fn sparse_large_files_keep_u64_positions() -> io::Result<()> {
        let fixture = Fixture::new("large")?;
        let medium_path = fixture.file("above-64-mib.bin");
        let medium_len = 64 * 1024 * 1024 + 257;
        let medium_high_offset = 64 * 1024 * 1024_u64 + 123;
        sparse_file(
            &medium_path,
            medium_len,
            &[
                (0, b"HEAD"),
                (MAX_READ_BYTES as u64, b"EDGE"),
                (medium_high_offset, b"HIGH"),
                (medium_len - 1, b"Z"),
            ],
        )?;

        let medium = PagedFile::open(&medium_path)?;
        assert_eq!(&*medium.read_window(0, 4)?.bytes, b"HEAD");
        assert_eq!(
            &*medium.read_window(MAX_READ_BYTES as u64, 4)?.bytes,
            b"EDGE"
        );
        assert_eq!(&*medium.read_window(medium_high_offset, 4)?.bytes, b"HIGH");
        assert_eq!(&*medium.read_window(medium_len - 1, 8)?.bytes, b"Z");

        let large_path = fixture.file("above-4-gib.bin");
        let large_len = 4 * 1024 * 1024 * 1024_u64 + 4097;
        let high_offset = 4 * 1024 * 1024 * 1024_u64 + 123;
        sparse_file(
            &large_path,
            large_len,
            &[
                (0, b"HEAD"),
                (MAX_READ_BYTES as u64, b"EDGE"),
                (high_offset, b"HIGH"),
                (large_len - 1, b"Q"),
            ],
        )?;

        let large = PagedFile::open(&large_path)?;
        assert_eq!(large.len(), large_len);
        assert_eq!(&*large.read_window(0, 4)?.bytes, b"HEAD");
        assert_eq!(
            &*large.read_window(MAX_READ_BYTES as u64, 4)?.bytes,
            b"EDGE"
        );
        assert_eq!(&*large.read_window(high_offset, 4)?.bytes, b"HIGH");
        assert_eq!(&*large.read_window(large_len - 1, 16)?.bytes, b"Q");
        Ok(())
    }

    /*
    A native pathname can contain bytes that UTF-8 cannot represent.
    PagedFile passes these bytes through Path without display conversion.
    */
    #[test]
    fn non_utf8_native_path_opens() -> io::Result<()> {
        let fixture = Fixture::new("native-path")?;
        let name = std::ffi::OsString::from_vec(b"native-\xFF.bin".to_vec());
        let path = fixture.path.join(name);
        fs::write(&path, b"native")?;

        let source = PagedFile::open(&path)?;
        assert_eq!(&*source.read_window(0, 6)?.bytes, b"native");
        Ok(())
    }

    /*
    Open preserves the operating-system error for a missing file.
    It also rejects a directory after a successful nonblocking open.
    */
    #[test]
    fn open_preserves_missing_errors_and_rejects_nonregular_sources() -> io::Result<()> {
        let fixture = Fixture::new("open-errors")?;
        assert_eq!(
            PagedFile::open(&fixture.file("missing.bin"))
                .err()
                .expect("a missing file must fail")
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            PagedFile::open(&fixture.path)
                .err()
                .expect("a directory must fail")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        Ok(())
    }

    /*
    The FIFO has no writer when PagedFile opens it.
    O_NONBLOCK lets open continue to metadata validation and regular-file refusal.
    The check command also gives this test a process deadline.
    */
    #[test]
    fn fifo_is_rejected_without_blocking() -> io::Result<()> {
        let fixture = Fixture::new("fifo")?;
        let path = fixture.file("source.fifo");
        let pathname = CString::new(path.as_os_str().as_bytes())?;
        if unsafe { mkfifo(pathname.as_ptr(), 0o600) } != 0 {
            return Err(io::Error::last_os_error());
        }

        assert_eq!(
            PagedFile::open(&path)
                .err()
                .expect("a FIFO must fail")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        Ok(())
    }

    /*
    An explicit modification time change provides a deterministic source-change signal.
    The test does not depend on filesystem timestamp speed or a sleep interval.
    */
    #[test]
    fn modification_time_change_requires_reopen() -> io::Result<()> {
        let fixture = Fixture::new("changed")?;
        let path = fixture.file("source.bin");
        fs::write(&path, b"unchanged length")?;
        let source = PagedFile::open(&path)?;

        let file = OpenOptions::new().write(true).open(&path)?;
        let times = FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1));
        file.set_times(times)?;
        assert!(
            source
                .read_window(0, 1)
                .unwrap_err()
                .to_string()
                .contains("Reopen")
        );
        Ok(())
    }

    /*
    Truncation changes the captured length before a positioned read starts.
    The component returns an error and cannot return a partial completed window.
    */
    #[test]
    fn truncation_returns_no_completed_window() -> io::Result<()> {
        let fixture = Fixture::new("truncated")?;
        let path = fixture.file("source.bin");
        fs::write(&path, b"abcdefgh")?;
        let source = PagedFile::open(&path)?;

        OpenOptions::new().write(true).open(&path)?.set_len(3)?;
        assert!(
            source
                .read_window(0, 8)
                .unwrap_err()
                .to_string()
                .contains("shrank")
        );
        Ok(())
    }
}
