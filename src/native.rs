use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const RTLD_NOW: c_int = 2;
const RTLD_LOCAL: c_int = 0;

#[link(name = "dl")]
unsafe extern "C" {
    fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dlerror() -> *const c_char;
}

pub struct Library {
    handle: *mut c_void,
    name: &'static str,
}

impl Library {
    pub fn open(name: &'static str) -> Result<Self, String> {
        let path = library_path(name)?;
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| format!("The {name} path contains a zero byte."))?;
        let handle = unsafe { dlopen(path.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
        if handle.is_null() {
            return Err(format!("Cannot load {name}: {}", loader_error()));
        }
        Ok(Self { handle, name })
    }

    pub fn symbol(&self, name: &'static [u8]) -> Result<*mut c_void, String> {
        debug_assert_eq!(name.last(), Some(&0));
        unsafe {
            dlerror();
        }
        let address = unsafe { dlsym(self.handle, name.as_ptr().cast()) };
        let error = unsafe { dlerror() };
        if !error.is_null() || address.is_null() {
            let symbol = CStr::from_bytes_with_nul(name).unwrap().to_string_lossy();
            let detail = if error.is_null() {
                "The dynamic loader did not provide an error.".into()
            } else {
                unsafe { CStr::from_ptr(error) }
                    .to_string_lossy()
                    .into_owned()
            };
            return Err(format!("{} lacks {symbol}: {detail}", self.name));
        }
        Ok(address)
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        unsafe {
            dlclose(self.handle);
        }
    }
}

fn library_path(name: &str) -> Result<PathBuf, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let sibling = executable.with_file_name(name);
    if sibling.is_file()
        || std::env::var_os("HVIEW_PORTABLE").as_deref() == Some(std::ffi::OsStr::new("1"))
    {
        return sibling
            .canonicalize()
            .map_err(|_| format!("Cannot find {name}. Place the library beside the executable."));
    }
    let source = Path::new(option_env!("CARGO_MANIFEST_DIR").unwrap_or("."))
        .join("lib")
        .join(name);
    source
        .canonicalize()
        .map_err(|_| format!("Cannot find {name}. Place the library beside the executable."))
}

fn loader_error() -> String {
    let error = unsafe { dlerror() };
    if error.is_null() {
        "The dynamic loader did not provide an error.".into()
    } else {
        unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_library_reports_its_name() {
        let error = Library::open("libhview-missing.so").err().unwrap();
        assert!(error.contains("libhview-missing.so"));
    }
}
