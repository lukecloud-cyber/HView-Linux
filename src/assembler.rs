use crate::native::Library;
use std::ffi::{CStr, CString, c_char, c_void};

pub fn assemble(text: &str, bits: u32, address: u64) -> Result<Vec<u8>, String> {
    let mode = match bits {
        16 => 2,
        32 => 4,
        64 => 8,
        _ => return Err("The assembler supports only 16, 32, or 64 bits.".into()),
    };
    let text = text.trim();
    if text.is_empty() || !text.is_ascii() || text.len() > 350 || text.contains(['\n', '\r', ';']) {
        return Err("Enter one ASCII instruction with no more than 350 characters.".into());
    }
    if text.eq_ignore_ascii_case("int3") {
        return Err("Illegal instruction".into());
    }
    let normalized = if text.eq_ignore_ascii_case("retn") {
        "ret"
    } else {
        text
    };
    let instruction =
        CString::new(normalized).map_err(|_| "The instruction contains a NUL byte.")?;
    let library = Library::open("libkeystone.so")?;
    macro_rules! symbol {
        ($name:literal, $kind:ty) => {{
            let pointer = library.symbol(concat!($name, "\0").as_bytes())?;
            unsafe { std::mem::transmute::<*mut c_void, $kind>(pointer) }
        }};
    }
    let version = symbol!(
        "ks_version",
        unsafe extern "C" fn(*mut u32, *mut u32) -> u32
    );
    let open = symbol!(
        "ks_open",
        unsafe extern "C" fn(u32, u32, *mut *mut c_void) -> i32
    );
    let option = symbol!(
        "ks_option",
        unsafe extern "C" fn(*mut c_void, i32, usize) -> i32
    );
    let asm = symbol!(
        "ks_asm",
        unsafe extern "C" fn(
            *mut c_void,
            *const c_char,
            u64,
            *mut *mut u8,
            *mut usize,
            *mut usize,
        ) -> i32
    );
    let errno = symbol!("ks_errno", unsafe extern "C" fn(*mut c_void) -> i32);
    let strerror = symbol!("ks_strerror", unsafe extern "C" fn(i32) -> *const c_char);
    let free = symbol!("ks_free", unsafe extern "C" fn(*mut u8));
    let close = symbol!("ks_close", unsafe extern "C" fn(*mut c_void) -> i32);
    let (mut major, mut minor) = (0, 0);
    unsafe {
        version(&mut major, &mut minor);
    }
    if (major, minor) != (0, 9) {
        return Err(format!(
            "Unsupported Keystone API version {major}.{minor}. Use version 0.9."
        ));
    }
    let mut engine = std::ptr::null_mut();
    if unsafe { open(4, mode, &mut engine) } != 0 {
        return Err("Cannot initialize the x86 assembler.".into());
    }
    let mut bytes = std::ptr::null_mut();
    let (mut size, mut count) = (0, 0);
    let result = if unsafe { option(engine, 1, 33) } != 0 {
        Err("Cannot select Intel syntax with hexadecimal numbers.".into())
    } else if unsafe {
        asm(
            engine,
            instruction.as_ptr(),
            address,
            &mut bytes,
            &mut size,
            &mut count,
        )
    } != 0
    {
        let message = unsafe { strerror(errno(engine)) };
        Err(if message.is_null() {
            "Illegal instruction".into()
        } else {
            format!(
                "Cannot assemble this instruction: {}",
                unsafe { CStr::from_ptr(message) }.to_string_lossy()
            )
        })
    } else if bytes.is_null() || count != 1 || !(1..=15).contains(&size) {
        Err("The assembler did not produce one valid x86 instruction.".into())
    } else {
        let mut output = unsafe { std::slice::from_raw_parts(bytes, size) }.to_vec();
        // HView preserves the one-byte INT 3 encoding and the 16-bit near return.
        if output == [0xcd, 3] {
            output = vec![0xcc];
        }
        if bits == 16 && normalized.eq_ignore_ascii_case("ret") && output == [0x66, 0xc3] {
            output = vec![0xc3];
        }
        Ok(output)
    };
    unsafe {
        if !bytes.is_null() {
            free(bytes);
        }
        close(engine);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn assembler_vectors_and_errors() {
        assert_eq!(assemble("int 3", 16, 0).unwrap(), [0xcc]);
        assert_eq!(assemble("ret", 16, 0).unwrap(), [0xc3]);
        assert_eq!(assemble("nop", 32, 0).unwrap(), [0x90]);
        assert_eq!(assemble("mov ax,10", 16, 0).unwrap(), [0xb8, 0x10, 0]);
        assert_eq!(assemble("mov rax,rbx", 64, 0).unwrap(), [0x48, 0x89, 0xd8]);
        assert_eq!(assemble("jmp 1005", 32, 0x1000).unwrap(), [0xeb, 3]);
        for text in ["", "int3", "unknown_opcode", "nop; nop", "nop\0"] {
            assert!(assemble(text, 32, 0).is_err());
        }
        assert!(assemble("nop", 8, 0).is_err());
    }
}
