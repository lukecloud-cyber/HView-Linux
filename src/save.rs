use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const O_RDWR: c_int = 2;
const O_CREAT: c_int = 0o100;
const O_EXCL: c_int = 0o200;
const O_NONBLOCK: c_int = 0o4000;
const O_CLOEXEC: c_int = 0o2000000;
const O_DIRECTORY: c_int = 0o200000;
const O_NOFOLLOW: c_int = 0o400000;
const O_PATH: c_int = 0o10000000;
const AT_REMOVEDIR: c_int = 0x200;
const RENAME_NOREPLACE: u32 = 1;
const ELOOP: i32 = 40;
const ENODATA: i32 = 61;
const ERANGE: i32 = 34;
const ENOTSUP: i32 = 95;

const NEW_FILE: &CStr = c"new.bin";
const ORIGINAL_FILE: &CStr = c"original.bin";
const TARGET_FILE: &CStr = c"target.txt";

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

unsafe extern "C" {
    fn openat(dirfd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    fn mkdirat(dirfd: c_int, path: *const c_char, mode: u32) -> c_int;
    fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int;
    fn renameat(
        olddirfd: c_int,
        oldpath: *const c_char,
        newdirfd: c_int,
        newpath: *const c_char,
    ) -> c_int;
    fn renameat2(
        olddirfd: c_int,
        oldpath: *const c_char,
        newdirfd: c_int,
        newpath: *const c_char,
        flags: u32,
    ) -> c_int;
    fn fchown(fd: c_int, owner: u32, group: u32) -> c_int;
    fn futimens(fd: c_int, times: *const Timespec) -> c_int;
    fn geteuid() -> u32;
    fn flistxattr(fd: c_int, list: *mut c_char, size: usize) -> isize;
    fn fgetxattr(fd: c_int, name: *const c_char, value: *mut c_void, size: usize) -> isize;
    fn fsetxattr(
        fd: c_int,
        name: *const c_char,
        value: *const c_void,
        size: usize,
        flags: c_int,
    ) -> c_int;
    fn fremovexattr(fd: c_int, name: *const c_char) -> c_int;
    #[cfg(test)]
    fn symlinkat(target: *const c_char, newdirfd: c_int, linkpath: *const c_char) -> c_int;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileState {
    dev: u64,
    ino: u64,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Clone)]
struct SourceMetadata {
    state: FileState,
    atime: i64,
    atime_nsec: i64,
}

struct Target {
    parent_path: PathBuf,
    path: PathBuf,
    parent: File,
    name: CString,
}

struct Stage {
    folder_name: CString,
    folder_path: PathBuf,
    parent: File,
    dir: File,
    keep: bool,
}

fn os_name(name: &std::ffi::OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "The save path contains a zero character.",
        )
    })
}

fn target(path: &Path) -> io::Result<Target> {
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| io::Error::other("Enter a file name."))?;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_path = fs::canonicalize(parent)?;
    let parent_file = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_CLOEXEC)
        .open(&parent_path)?;
    Ok(Target {
        path: parent_path.join(name),
        parent_path,
        parent: parent_file,
        name: os_name(name)?,
    })
}

fn open_at(dir: RawFd, name: &CStr, flags: c_int, mode: u32) -> io::Result<File> {
    let fd = unsafe { openat(dir, name.as_ptr(), flags, mode) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn open_target(target: &Target) -> io::Result<File> {
    open_at(
        target.parent.as_raw_fd(),
        &target.name,
        O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
        0,
    )
    .map_err(|error| {
        if error.raw_os_error() == Some(ELOOP) {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "The save target is a symbolic link. Use Save As with a new file name.",
            )
        } else if error.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "The save target is not writable. Use Save As with a new file name.",
            )
        } else {
            error
        }
    })
}

fn inspect_target(target: &Target) -> io::Result<()> {
    let file = open_at(
        target.parent.as_raw_fd(),
        &target.name,
        O_PATH | O_CLOEXEC | O_NOFOLLOW,
        0,
    )?;
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "The save target is a symbolic link. Use Save As with a new file name.",
        ));
    }
    require_regular(&metadata)?;
    require_unprivileged_mode(&metadata)
}

fn changed() -> io::Error {
    io::Error::other("The file changed outside the editor. Reload the file before saving.")
}

fn require_regular(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.file_type().is_file() {
        return Err(io::Error::other(
            "The save target is not a regular file. Use Save As with a new file name.",
        ));
    }
    if metadata.nlink() != 1 {
        return Err(io::Error::other(
            "The save target has multiple hard links. Use Save As to keep linked files unchanged.",
        ));
    }
    Ok(())
}

fn require_unprivileged_mode(metadata: &fs::Metadata) -> io::Result<()> {
    if metadata.mode() & 0o6000 != 0 {
        return Err(io::Error::other(
            "The save target has set-user-ID or set-group-ID permission. Use Save As with a new file name.",
        ));
    }
    Ok(())
}

fn is_no_xattr(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(ENODATA | ENOTSUP))
}

fn xattr_value(file: &File, name: &CStr) -> io::Result<Vec<u8>> {
    for _ in 0..8 {
        let size = unsafe { fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ENODATA) {
                return Err(changed());
            }
            return Err(error);
        }
        let mut value = vec![0; size as usize];
        let read = unsafe {
            fgetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if read >= 0 {
            value.truncate(read as usize);
            return Ok(value);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERANGE) {
            return Err(error);
        }
    }
    Err(changed())
}

fn check_xattr_name(name: &[u8]) -> io::Result<()> {
    if name.starts_with(b"user.") || name == b"system.posix_acl_access" {
        return Ok(());
    }
    let kind = if name.starts_with(b"security.") || name.starts_with(b"trusted.") {
        "privileged"
    } else {
        "unsupported"
    };
    Err(io::Error::other(format!(
        "The file has {kind} metadata '{}'. Use Save As to preserve the original file.",
        String::from_utf8_lossy(name)
    )))
}

fn xattrs(file: &File) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    for _ in 0..8 {
        let size = unsafe { flistxattr(file.as_raw_fd(), std::ptr::null_mut(), 0) };
        if size < 0 {
            let error = io::Error::last_os_error();
            return if is_no_xattr(&error) {
                Ok(Vec::new())
            } else {
                Err(error)
            };
        }
        let mut list = vec![0_u8; size as usize];
        let read = unsafe { flistxattr(file.as_raw_fd(), list.as_mut_ptr().cast(), list.len()) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERANGE) {
                continue;
            }
            return Err(error);
        }
        list.truncate(read as usize);
        let mut result = Vec::new();
        for bytes in list
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
        {
            let name = CString::new(bytes).map_err(|_| changed())?;
            check_xattr_name(bytes)?;
            result.push((bytes.to_vec(), xattr_value(file, &name)?));
        }
        result.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        return Ok(result);
    }
    Err(changed())
}

fn file_state(file: &File) -> io::Result<FileState> {
    let metadata = file.metadata()?;
    Ok(FileState {
        dev: metadata.dev(),
        ino: metadata.ino(),
        size: metadata.size(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        nlink: metadata.nlink(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
        xattrs: xattrs(file)?,
    })
}

fn source_metadata(file: &File) -> io::Result<SourceMetadata> {
    let metadata = file.metadata()?;
    require_regular(&metadata)?;
    require_unprivileged_mode(&metadata)?;
    Ok(SourceMetadata {
        state: file_state(file)?,
        atime: metadata.atime(),
        atime_nsec: metadata.atime_nsec(),
    })
}

fn check_contents(file: &mut File, expected: &[u8]) -> io::Result<()> {
    let length = u64::try_from(expected.len())
        .map_err(|_| io::Error::other("The file is too large to save."))?;
    if file.metadata()?.len() != length {
        return Err(changed());
    }
    file.seek(SeekFrom::Start(0))?;
    let mut buffer = [0_u8; 65536];
    for chunk in expected.chunks(buffer.len()) {
        if let Err(error) = file.read_exact(&mut buffer[..chunk.len()]) {
            return if error.kind() == io::ErrorKind::UnexpectedEof {
                Err(changed())
            } else {
                Err(error)
            };
        }
        if &buffer[..chunk.len()] != chunk {
            return Err(changed());
        }
    }
    Ok(())
}

fn set_xattrs(file: &File, attrs: &[(Vec<u8>, Vec<u8>)]) -> io::Result<()> {
    for (name, _) in xattrs(file)? {
        let name = CString::new(name).map_err(|_| changed())?;
        if unsafe { fremovexattr(file.as_raw_fd(), name.as_ptr()) } < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ENODATA) {
                return Err(error);
            }
        }
    }
    for (name, value) in attrs {
        let name = CString::new(name.as_slice()).map_err(|_| changed())?;
        if unsafe {
            fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        } < 0
        {
            return Err(io::Error::other(format!(
                "The save cannot preserve metadata '{}': {}",
                String::from_utf8_lossy(name.as_bytes()),
                io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

fn apply_metadata(file: &File, source: &SourceMetadata) -> io::Result<()> {
    let current = file.metadata()?;
    if (current.uid(), current.gid()) != (source.state.uid, source.state.gid)
        && unsafe { fchown(file.as_raw_fd(), source.state.uid, source.state.gid) } < 0
    {
        return Err(io::Error::other(format!(
            "The save cannot preserve the file owner and group: {}",
            io::Error::last_os_error()
        )));
    }
    file.set_permissions(fs::Permissions::from_mode(source.state.mode & 0o7777))?;
    set_xattrs(file, &source.state.xattrs)?;
    verify_metadata(file, source)
}

fn verify_metadata(file: &File, source: &SourceMetadata) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.uid() != source.state.uid
        || metadata.gid() != source.state.gid
        || metadata.mode() & 0o7777 != source.state.mode & 0o7777
        || xattrs(file)? != source.state.xattrs
    {
        return Err(io::Error::other(
            "The save cannot preserve the file metadata. The original file remains unchanged.",
        ));
    }
    Ok(())
}

fn set_original_times(file: &File, source: &SourceMetadata) -> io::Result<()> {
    let times = [
        Timespec {
            tv_sec: source.atime,
            tv_nsec: source.atime_nsec,
        },
        Timespec {
            tv_sec: source.state.mtime,
            tv_nsec: source.state.mtime_nsec,
        },
    ];
    if unsafe { futimens(file.as_raw_fd(), times.as_ptr()) } < 0 {
        return Err(io::Error::other(format!(
            "The save cannot preserve the backup timestamps: {}",
            io::Error::last_os_error()
        )));
    }
    let metadata = file.metadata()?;
    if (
        metadata.atime(),
        metadata.atime_nsec(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    ) != (
        source.atime,
        source.atime_nsec,
        source.state.mtime,
        source.state.mtime_nsec,
    ) {
        return Err(io::Error::other(
            "The save cannot preserve the backup timestamps.",
        ));
    }
    Ok(())
}

fn random_folder_name() -> io::Result<CString> {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut name = String::from(".HView-save-");
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut name, "{byte:02x}").expect("Writing to a string cannot fail.");
    }
    Ok(CString::new(name).expect("A generated folder name cannot contain a zero character."))
}

impl Stage {
    fn new(target: &Target) -> io::Result<Self> {
        let parent = target.parent.try_clone()?;
        loop {
            let folder_name = random_folder_name()?;
            if unsafe { mkdirat(target.parent.as_raw_fd(), folder_name.as_ptr(), 0o700) } < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::AlreadyExists {
                    continue;
                }
                return Err(error);
            }
            #[cfg(test)]
            substitute_stage_name(target.parent.as_raw_fd(), &folder_name)?;
            let dir = match open_at(
                target.parent.as_raw_fd(),
                &folder_name,
                O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW,
                0,
            ) {
                Ok(dir) => dir,
                Err(error) => {
                    unsafe {
                        unlinkat(
                            target.parent.as_raw_fd(),
                            folder_name.as_ptr(),
                            AT_REMOVEDIR,
                        );
                    }
                    return Err(error);
                }
            };
            let metadata = match dir.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    unsafe {
                        unlinkat(
                            target.parent.as_raw_fd(),
                            folder_name.as_ptr(),
                            AT_REMOVEDIR,
                        );
                    }
                    return Err(error);
                }
            };
            if !metadata.is_dir() || metadata.uid() != unsafe { geteuid() } {
                unsafe {
                    unlinkat(
                        target.parent.as_raw_fd(),
                        folder_name.as_ptr(),
                        AT_REMOVEDIR,
                    );
                }
                return Err(io::Error::other(
                    "The save cannot create a private recovery directory.",
                ));
            }
            dir.set_permissions(fs::Permissions::from_mode(0o700))?;
            if dir.metadata()?.mode() & 0o777 != 0o700 {
                unsafe {
                    unlinkat(
                        target.parent.as_raw_fd(),
                        folder_name.as_ptr(),
                        AT_REMOVEDIR,
                    );
                }
                return Err(io::Error::other(
                    "The save cannot protect the recovery directory.",
                ));
            }
            let folder_os = std::ffi::OsString::from_vec(folder_name.as_bytes().to_vec());
            let mut stage = Self {
                folder_path: target.parent_path.join(folder_os),
                folder_name,
                parent,
                dir,
                keep: false,
            };
            stage.write_note(&target.path)?;
            return Ok(stage);
        }
    }

    fn write_note(&mut self, target: &Path) -> io::Result<()> {
        let mut note = self.create(TARGET_FILE, 0o600)?;
        note.write_all(target.as_os_str().as_bytes())?;
        note.write_all(b"\n")?;
        note.sync_all()
    }

    fn create(&self, name: &CStr, mode: u32) -> io::Result<File> {
        open_at(
            self.dir.as_raw_fd(),
            name,
            O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            mode,
        )
    }

    fn write_data(&self, name: &CStr, data: &[u8], mode: u32) -> io::Result<File> {
        let mut file = self.create(name, mode)?;
        #[cfg(test)]
        if take_fault(FAULT_WRITE) {
            file.write_all(&data[..data.len() / 2])?;
            return Err(injected("staging write"));
        }
        file.write_all(data)?;
        Ok(file)
    }

    fn sync_preparation(&self) -> io::Result<()> {
        self.dir.sync_all()?;
        #[cfg(test)]
        if take_fault(FAULT_PRE_SYNC) {
            return Err(injected("prepublication synchronization"));
        }
        self.parent.sync_all()
    }

    fn recovery_error(&self, error: io::Error, published: bool) -> io::Error {
        let message = if published {
            format!(
                "Publication finished, but final synchronization failed. New bytes may already be visible. Recovery files remain in {}. Error: {error}",
                self.folder_path.display()
            )
        } else {
            format!(
                "Save publication failed. Recovery files remain in {}. Error: {error}",
                self.folder_path.display()
            )
        };
        io::Error::new(error.kind(), message)
    }

    fn publish(&mut self, target: &Target, replace: bool) -> io::Result<()> {
        self.keep = true;
        #[cfg(test)]
        if take_fault(FAULT_PUBLISH) {
            let error = injected("publication");
            return Err(self.recovery_error(error, false));
        }
        // An uncooperative writer can change the target after the final check and before this rename.
        let result = unsafe {
            if replace {
                renameat(
                    self.dir.as_raw_fd(),
                    NEW_FILE.as_ptr(),
                    target.parent.as_raw_fd(),
                    target.name.as_ptr(),
                )
            } else {
                renameat2(
                    self.dir.as_raw_fd(),
                    NEW_FILE.as_ptr(),
                    target.parent.as_raw_fd(),
                    target.name.as_ptr(),
                    RENAME_NOREPLACE,
                )
            }
        };
        if result < 0 {
            return Err(self.recovery_error(io::Error::last_os_error(), false));
        }
        #[cfg(test)]
        if take_fault(FAULT_FINAL_SYNC) {
            let error = injected("final synchronization");
            return Err(self.recovery_error(error, true));
        }
        self.dir
            .sync_all()
            .map_err(|error| self.recovery_error(error, true))?;
        self.parent
            .sync_all()
            .map_err(|error| self.recovery_error(error, true))?;
        if !replace {
            self.keep = false;
        }
        Ok(())
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        for name in [NEW_FILE, ORIGINAL_FILE, TARGET_FILE] {
            unsafe {
                unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0);
            }
        }
        unsafe {
            unlinkat(
                self.parent.as_raw_fd(),
                self.folder_name.as_ptr(),
                AT_REMOVEDIR,
            );
        }
    }
}

fn prepare_backup(stage: &Stage, before: &[u8], source: &SourceMetadata) -> io::Result<File> {
    let mut backup = stage.write_data(ORIGINAL_FILE, before, 0o600)?;
    check_contents(&mut backup, before)?;
    apply_metadata(&backup, source)?;
    set_original_times(&backup, source)?;
    backup.sync_all()?;
    Ok(backup)
}

fn prepare_new(stage: &Stage, after: &[u8], source: Option<&SourceMetadata>) -> io::Result<File> {
    let mode = if source.is_some() { 0o600 } else { 0o666 };
    let mut new_file = stage.write_data(NEW_FILE, after, mode)?;
    if let Some(source) = source {
        apply_metadata(&new_file, source)?;
    }
    check_contents(&mut new_file, after)?;
    new_file.sync_all()?;
    Ok(new_file)
}

fn check_target(
    target: &Target,
    original: &mut File,
    expected: &FileState,
    before: &[u8],
) -> io::Result<()> {
    if file_state(original)? != *expected {
        return Err(changed());
    }
    check_contents(original, before)?;
    let mut current = open_target(target)?;
    require_regular(&current.metadata()?)?;
    if file_state(&current)? != *expected {
        return Err(changed());
    }
    check_contents(&mut current, before)
}

/// Replace a regular file and keep an independent backup beside the target.
///
/// Advisory locks coordinate only with processes that use compatible locks.
/// The replacement gets a new inode, change time, and birth time.
/// The backup retains the original access and modification times.
/// Cleanup errors can leave an incomplete recovery directory.
/// A power loss after publication and before directory synchronization makes the publication result uncertain.
pub fn replace(path: &Path, before: &[u8], after: &[u8]) -> io::Result<PathBuf> {
    let target = target(path)?;
    inspect_target(&target)?;
    let mut original = open_target(&target)?;
    original.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => {
            io::Error::other("The save target is in use. Close the other writer or use Save As.")
        }
        TryLockError::Error(error) => io::Error::other(format!(
            "The save cannot lock the target. Use Save As. Error: {error}"
        )),
    })?;
    let source = source_metadata(&original)?;
    check_contents(&mut original, before)?;

    let mut stage = Stage::new(&target)?;
    let _backup = prepare_backup(&stage, before, &source)?;
    let _new_file = prepare_new(&stage, after, Some(&source))?;
    stage.sync_preparation()?;
    check_target(&target, &mut original, &source.state, before)?;
    stage.publish(&target, true)?;
    Ok(stage
        .folder_path
        .join(std::ffi::OsStr::from_bytes(ORIGINAL_FILE.to_bytes())))
}

/// Create a file without replacing any existing destination entry.
/// Cleanup errors can leave an incomplete recovery directory.
/// A power loss after publication and before directory synchronization makes the publication result uncertain.
pub fn save_as(path: &Path, data: &[u8]) -> io::Result<PathBuf> {
    let target = target(path)?;
    let mut stage = Stage::new(&target)?;
    let _new_file = prepare_new(&stage, data, None)?;
    stage.sync_preparation()?;
    stage.publish(&target, false)?;
    Ok(target.path)
}

#[cfg(test)]
const FAULT_WRITE: u8 = 1;
#[cfg(test)]
const FAULT_PRE_SYNC: u8 = 2;
#[cfg(test)]
const FAULT_PUBLISH: u8 = 3;
#[cfg(test)]
const FAULT_FINAL_SYNC: u8 = 4;
#[cfg(test)]
const FAULT_STAGE_SUBSTITUTE: u8 = 5;

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static STAGE_SUBSTITUTE: std::cell::RefCell<Option<CString>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
fn set_fault(fault: u8) {
    FAULT.with(|value| value.set(fault));
}

#[cfg(test)]
fn set_stage_substitute(path: &Path) {
    let path = CString::new(path.as_os_str().as_bytes()).unwrap();
    STAGE_SUBSTITUTE.with(|value| *value.borrow_mut() = Some(path));
    set_fault(FAULT_STAGE_SUBSTITUTE);
}

#[cfg(test)]
fn substitute_stage_name(parent: RawFd, folder_name: &CStr) -> io::Result<()> {
    if !take_fault(FAULT_STAGE_SUBSTITUTE) {
        return Ok(());
    }
    let target = STAGE_SUBSTITUTE.with(|value| value.borrow_mut().take().unwrap());
    if unsafe { unlinkat(parent, folder_name.as_ptr(), AT_REMOVEDIR) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { symlinkat(target.as_ptr(), parent, folder_name.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
fn take_fault(fault: u8) -> bool {
    FAULT.with(|value| {
        if value.get() == fault {
            value.set(0);
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
fn injected(action: &str) -> io::Error {
    io::Error::other(format!("Injected {action} failure."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let name = random_folder_name().unwrap();
            let path = std::env::temp_dir().join(std::ffi::OsStr::from_bytes(name.as_bytes()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn recovery_dirs(&self) -> Vec<PathBuf> {
            fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| {
                    path.file_name()
                        .unwrap()
                        .as_bytes()
                        .starts_with(b".HView-save-")
                })
                .collect()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn set_test_xattr(file: &File, name: &CStr, value: &[u8]) {
        assert_eq!(
            unsafe {
                fsetxattr(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                )
            },
            0
        );
    }

    #[test]
    fn replace_preserves_bytes_metadata_and_independent_backup() {
        let fixture = Fixture::new();
        let path = fixture.0.join("sample.bin");
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        set_test_xattr(&file, c"user.hview-test", b"metadata");
        let times = [
            Timespec {
                tv_sec: 1_600_000_000,
                tv_nsec: 123_456_789,
            },
            Timespec {
                tv_sec: 1_600_000_001,
                tv_nsec: 987_654_321,
            },
        ];
        assert_eq!(unsafe { futimens(file.as_raw_fd(), times.as_ptr()) }, 0);
        let source = source_metadata(&file).unwrap();
        let old_inode = file.metadata().unwrap().ino();

        let backup = replace(&path, b"original", b"edited").unwrap();
        let backup_file = File::open(&backup).unwrap();
        let backup_metadata = backup_file.metadata().unwrap();
        assert_eq!(
            (backup_metadata.atime(), backup_metadata.atime_nsec()),
            (times[0].tv_sec, times[0].tv_nsec)
        );
        assert_eq!(
            (backup_metadata.mtime(), backup_metadata.mtime_nsec()),
            (times[1].tv_sec, times[1].tv_nsec)
        );
        assert_eq!(fs::read(&path).unwrap(), b"edited");
        assert_eq!(fs::read(&backup).unwrap(), b"original");
        let saved = File::open(&path).unwrap();
        assert_ne!(saved.metadata().unwrap().ino(), old_inode);
        assert_eq!(saved.metadata().unwrap().mode() & 0o7777, 0o640);
        assert_eq!(saved.metadata().unwrap().uid(), source.state.uid);
        assert_eq!(saved.metadata().unwrap().gid(), source.state.gid);
        assert_eq!(backup_metadata.mode() & 0o7777, 0o640);
        assert_eq!(backup_metadata.uid(), source.state.uid);
        assert_eq!(backup_metadata.gid(), source.state.gid);
        assert_eq!(xattrs(&saved).unwrap(), source.state.xattrs);
        assert_eq!(xattrs(&backup_file).unwrap(), source.state.xattrs);

        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"changed!").unwrap();
        assert_eq!(fs::read(&backup).unwrap(), b"original");
        assert_eq!(fs::read(&path).unwrap(), b"edited");
    }

    #[test]
    fn replace_rejects_content_path_links_and_locks() {
        let fixture = Fixture::new();
        let path = fixture.0.join("sample.bin");
        fs::write(&path, b"changed").unwrap();
        assert!(replace(&path, b"original", b"edit").is_err());
        assert!(
            replace(&fixture.0, b"", b"edit")
                .unwrap_err()
                .to_string()
                .contains("regular file")
        );

        let link = fixture.0.join("link.bin");
        symlink(&path, &link).unwrap();
        assert!(
            replace(&link, b"changed", b"edit")
                .unwrap_err()
                .to_string()
                .contains("symbolic link")
        );

        let hard = fixture.0.join("hard.bin");
        fs::hard_link(&path, &hard).unwrap();
        assert!(
            replace(&path, b"changed", b"edit")
                .unwrap_err()
                .to_string()
                .contains("hard links")
        );
        fs::remove_file(&hard).unwrap();

        let lock = File::open(&path).unwrap();
        lock.try_lock().unwrap();
        assert!(
            replace(&path, b"changed", b"edit")
                .unwrap_err()
                .to_string()
                .contains("in use")
        );
        drop(lock);

        let target = target(&path).unwrap();
        let original = open_target(&target).unwrap();
        let state = file_state(&original).unwrap();
        let moved = fixture.0.join("moved.bin");
        fs::rename(&path, &moved).unwrap();
        fs::write(&path, b"changed").unwrap();
        let mut original = original;
        assert!(check_target(&target, &mut original, &state, b"changed").is_err());
    }

    #[test]
    fn replace_rejects_read_only_and_privilege_modes() {
        let fixture = Fixture::new();
        let read_only = fixture.0.join("read-only.bin");
        fs::write(&read_only, b"original").unwrap();
        fs::set_permissions(&read_only, fs::Permissions::from_mode(0o444)).unwrap();
        let error = replace(&read_only, b"original", b"edited").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("Save As"));
        assert_eq!(fs::read(&read_only).unwrap(), b"original");

        for (name, mode) in [("setuid.bin", 0o4755), ("setgid.bin", 0o2755)] {
            let path = fixture.0.join(name);
            fs::write(&path, b"original").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, mode);
            let error = replace(&path, b"original", b"edited").unwrap_err();
            assert!(error.to_string().contains("set-user-ID or set-group-ID"));
            assert_eq!(fs::read(&path).unwrap(), b"original");
        }
        assert!(fixture.recovery_dirs().is_empty());
    }

    #[test]
    fn stage_name_substitution_does_not_change_victim_permissions() {
        let fixture = Fixture::new();
        let victim = fixture.0.join("victim.bin");
        fs::write(&victim, b"victim").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        set_stage_substitute(&victim);

        let target = fixture.0.join("new.bin");
        assert!(save_as(&target, b"new").is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o7777, 0o644);
        let residue = fixture.recovery_dirs();
        assert_eq!(residue.len(), 1);
        assert!(
            fs::symlink_metadata(&residue[0])
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn save_as_uses_atomic_destination_refusal() {
        let fixture = Fixture::new();
        let path = fixture.0.join("new.bin");
        assert_eq!(save_as(&path, b"new").unwrap(), path);
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(
            save_as(&path, b"overwrite").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&path).unwrap(), b"new");

        let dangling = fixture.0.join("dangling.bin");
        symlink(fixture.0.join("missing.bin"), &dangling).unwrap();
        assert_eq!(
            save_as(&dangling, b"overwrite").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(
            fs::symlink_metadata(&dangling)
                .unwrap()
                .file_type()
                .is_symlink()
        );

        let raced_path = fixture.0.join("raced.bin");
        let raced_target = target(&raced_path).unwrap();
        let mut stage = Stage::new(&raced_target).unwrap();
        let _new_file = prepare_new(&stage, b"staged", None).unwrap();
        stage.sync_preparation().unwrap();
        symlink(fixture.0.join("missing-raced.bin"), &raced_path).unwrap();
        assert_eq!(
            stage.publish(&raced_target, false).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            fs::read(stage.folder_path.join("new.bin")).unwrap(),
            b"staged"
        );
        assert!(
            fs::symlink_metadata(&raced_path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn failures_keep_or_remove_the_correct_recovery_data() {
        let fixture = Fixture::new();
        let path = fixture.0.join("new.bin");

        set_fault(FAULT_WRITE);
        assert!(save_as(&path, b"partial data").is_err());
        assert!(!path.exists());
        assert!(fixture.recovery_dirs().is_empty());

        set_fault(FAULT_PRE_SYNC);
        assert!(save_as(&path, b"prepared data").is_err());
        assert!(!path.exists());
        assert!(fixture.recovery_dirs().is_empty());

        set_fault(FAULT_PUBLISH);
        let error = save_as(&path, b"recover data").unwrap_err();
        assert!(error.to_string().contains("Recovery files remain"));
        let recovery = fixture.recovery_dirs();
        assert_eq!(recovery.len(), 1);
        assert_eq!(
            fs::read(recovery[0].join("new.bin")).unwrap(),
            b"recover data"
        );
        fs::remove_dir_all(&recovery[0]).unwrap();

        set_fault(FAULT_FINAL_SYNC);
        let error = save_as(&path, b"visible data").unwrap_err();
        assert!(error.to_string().contains("may already be visible"));
        assert_eq!(fs::read(&path).unwrap(), b"visible data");
        assert_eq!(fixture.recovery_dirs().len(), 1);
        for recovery in fixture.recovery_dirs() {
            fs::remove_dir_all(recovery).unwrap();
        }

        let replace_path = fixture.0.join("replace.bin");
        fs::write(&replace_path, b"original").unwrap();
        set_fault(FAULT_PUBLISH);
        let error = replace(&replace_path, b"original", b"edited").unwrap_err();
        assert!(error.to_string().contains("Recovery files remain"));
        assert_eq!(fs::read(&replace_path).unwrap(), b"original");
        let recovery = fixture.recovery_dirs();
        assert_eq!(recovery.len(), 1);
        assert_eq!(
            fs::read(recovery[0].join("original.bin")).unwrap(),
            b"original"
        );
        assert_eq!(fs::read(recovery[0].join("new.bin")).unwrap(), b"edited");
        fs::remove_dir_all(&recovery[0]).unwrap();

        set_fault(FAULT_FINAL_SYNC);
        let error = replace(&replace_path, b"original", b"edited").unwrap_err();
        assert!(error.to_string().contains("may already be visible"));
        assert_eq!(fs::read(&replace_path).unwrap(), b"edited");
        let recovery = fixture.recovery_dirs();
        assert_eq!(recovery.len(), 1);
        assert_eq!(
            fs::read(recovery[0].join("original.bin")).unwrap(),
            b"original"
        );
    }

    #[test]
    fn acl_and_metadata_policy_are_explicit() {
        let fixture = Fixture::new();
        let path = fixture.0.join("acl.bin");
        let plain_path = fixture.0.join("plain.bin");
        fs::write(&path, b"original").unwrap();
        fs::write(&plain_path, b"plain").unwrap();
        let status = Command::new("setfacl")
            .args(["-m", "u:1:r--"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        let status = Command::new("setfacl")
            .args(["-m", "d:u:1:r--"])
            .arg(&fixture.0)
            .status()
            .unwrap();
        assert!(status.success());
        let original = File::open(&path).unwrap();
        let acl = xattrs(&original).unwrap();
        assert!(
            acl.iter()
                .any(|(name, _)| name == b"system.posix_acl_access")
        );
        let backup = replace(&path, b"original", b"edited").unwrap();
        assert_eq!(xattrs(&File::open(&path).unwrap()).unwrap(), acl);
        assert_eq!(xattrs(&File::open(backup).unwrap()).unwrap(), acl);

        let plain_attrs = xattrs(&File::open(&plain_path).unwrap()).unwrap();
        assert!(plain_attrs.is_empty());
        let plain_backup = replace(&plain_path, b"plain", b"edited").unwrap();
        assert!(
            xattrs(&File::open(&plain_path).unwrap())
                .unwrap()
                .is_empty()
        );
        assert!(
            xattrs(&File::open(plain_backup).unwrap())
                .unwrap()
                .is_empty()
        );

        assert!(check_xattr_name(b"user.note").is_ok());
        assert!(check_xattr_name(b"system.posix_acl_access").is_ok());
        assert!(
            check_xattr_name(b"security.capability")
                .unwrap_err()
                .to_string()
                .contains("privileged")
        );
        assert!(check_xattr_name(b"system.unknown").is_err());
    }

    #[test]
    fn staging_failure_does_not_change_a_target() {
        let fixture = Fixture::new();
        let path = fixture.0.join("missing").join("new.bin");
        assert_eq!(
            save_as(&path, b"data").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(!path.exists());
    }

    #[test]
    fn empty_large_and_unicode_files_save() {
        let fixture = Fixture::new();
        let path = fixture.0.join("large.bin");
        let data = vec![0xa5; 131_073];
        fs::write(&path, &data).unwrap();
        let backup = replace(&path, &data, b"").unwrap();
        assert!(fs::read(&path).unwrap().is_empty());
        assert_eq!(fs::read(backup).unwrap(), data);

        let unicode = fixture.0.join("données.bin");
        assert_eq!(save_as(&unicode, b"new").unwrap(), unicode);
        assert_eq!(fs::read(unicode).unwrap(), b"new");
    }
}
