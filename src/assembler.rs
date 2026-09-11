/*
This module validates one instruction and assembles it through the pinned Keystone interface.
The architecture boundary selects x86, ARM, or Thumb and rejects ARM64 before library loading.
*/
use crate::format::Architecture;
use crate::native::Library;
use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::Mutex;

/*
These constants match the pinned Keystone 0.9.2 architecture, mode, and syntax values.
The Linux loader resolves the corresponding functions from one existing native library.
*/
const KS_ARCH_ARM: u32 = 1;
const KS_ARCH_X86: u32 = 4;
const KS_MODE_ARM: u32 = 1;
const KS_MODE_X86_16: u32 = 2;
const KS_MODE_X86_32: u32 = 4;
const KS_MODE_X86_64: u32 = 8;
const KS_MODE_THUMB: u32 = 0x10;
const KS_OPT_SYNTAX: i32 = 1;
const KS_OPT_SYNTAX_INTEL: usize = 1;
const KS_OPT_SYNTAX_RADIX16: usize = 32;

/*
This process lock covers Keystone loading and assembly.
It prevents concurrent first-use initialization inside the native library.
*/
static KEYSTONE_LOCK: Mutex<()> = Mutex::new(());

/*
This compatibility wrapper converts an existing x86 width into the shared architecture contract.
The architecture entry point performs the final engine-boundary validation.
*/
#[allow(
    dead_code,
    reason = "The x86 width wrapper remains for compatibility callers."
)]
pub fn assemble(text: &str, bits: u32, address: u64) -> Result<Vec<u8>, String> {
    let architecture = Architecture::x86(bits)
        .map_err(|_| "The assembler supports only 16, 32, or 64 bits.".to_owned())?;
    assemble_architecture(text, architecture, address)
}

/*
This entry point validates the architecture and prepares one Keystone request.
It supports x86, ARM, and Thumb while ARM64 assembly remains unsupported.
*/
pub fn assemble_architecture(
    text: &str,
    architecture: Architecture,
    address: u64,
) -> Result<Vec<u8>, String> {
    let (native_architecture, mode, name, x86_bits) = match architecture {
        Architecture::X86(16) => (KS_ARCH_X86, KS_MODE_X86_16, "x86", Some(16)),
        Architecture::X86(32) => (KS_ARCH_X86, KS_MODE_X86_32, "x86", Some(32)),
        Architecture::X86(64) => (KS_ARCH_X86, KS_MODE_X86_64, "x86", Some(64)),
        Architecture::X86(_) => {
            return Err("The assembler supports only 16, 32, or 64 bits.".into());
        }
        Architecture::Arm => (KS_ARCH_ARM, KS_MODE_ARM, "ARM", None),
        Architecture::Thumb => (KS_ARCH_ARM, KS_MODE_THUMB, "Thumb", None),
        Architecture::Arm64 => return Err("ARM64 assembly is unsupported.".into()),
    };

    /*
    The input checks preserve the ASCII, length, and single-instruction contract.
    X86 compatibility normalization happens before the text enters Keystone.
    ARM-family text enters Keystone without x86 substitutions.
    */
    let text = text.trim();
    if text.is_empty() || !text.is_ascii() || text.len() > 350 || text.contains(['\n', '\r', ';']) {
        return Err("Enter one ASCII instruction with no more than 350 characters.".into());
    }
    if x86_bits.is_some() && text.eq_ignore_ascii_case("int3") {
        return Err("Illegal instruction".into());
    }
    let normalized = if x86_bits.is_some() && text.eq_ignore_ascii_case("retn") {
        "ret"
    } else {
        text
    };
    let instruction =
        CString::new(normalized).map_err(|_| "The instruction contains a NUL byte.")?;
    /*
    The process lock covers native loading and assembly for safe concurrent first use.
    The loader resolves the fixed Keystone 0.9.2 ABI from the normal Linux library path.
    Each symbol keeps its native signature for the request below.
    */
    let _guard = KEYSTONE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    if unsafe { open(native_architecture, mode, &mut engine) } != 0 {
        return Err(format!("Cannot initialize the {name} assembler."));
    }
    /*
    X86 assembly selects Intel syntax and hexadecimal-number support.
    ARM and Thumb use their native Keystone syntax without this x86 option.
    Output validation rejects malformed native results before Rust copies the bytes.
    */
    let mut bytes = std::ptr::null_mut();
    let (mut size, mut count) = (0, 0);
    let result = if x86_bits.is_some()
        && unsafe {
            option(
                engine,
                KS_OPT_SYNTAX,
                KS_OPT_SYNTAX_INTEL | KS_OPT_SYNTAX_RADIX16,
            )
        } != 0
    {
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
    } else if bytes.is_null() || count != 1 || !architecture.valid_instruction_bytes(size) {
        Err(format!(
            "The assembler did not produce one valid {name} instruction."
        ))
    } else {
        let mut output = unsafe { std::slice::from_raw_parts(bytes, size) }.to_vec();
        /*
        X86 compatibility normalization preserves one-byte INT 3 and the 16-bit near return.
        ARM-family output remains unchanged after validation.
        */
        if x86_bits.is_some() && output == [0xcd, 3] {
            output = vec![0xcc];
        }
        if x86_bits == Some(16) && normalized.eq_ignore_ascii_case("ret") && output == [0x66, 0xc3]
        {
            output = vec![0xc3];
        }
        Ok(output)
    };
    /*
    Cleanup releases native output and the engine for all result paths.
    The returned vector owns its bytes after cleanup completes.
    */
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
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::Duration;

    /*
    This helper runs deterministic x86, ARM, Thumb, and error requests.
    Concurrent callers use the helper to exercise protected native first use.
    */
    fn known_result(case: usize) -> Result<(), String> {
        let (text, architecture, expected) = match case % 4 {
            0 => ("nop", Architecture::X86(32), &[0x90][..]),
            1 => (
                "mov r0, r0",
                Architecture::Arm,
                &[0x00, 0x00, 0xa0, 0xe1][..],
            ),
            2 => ("movs r0, #1", Architecture::Thumb, &[0x01, 0x20][..]),
            _ => {
                return match assemble_architecture("unknown_opcode", Architecture::Thumb, 0x1000) {
                    Ok(bytes) => Err(format!("Unexpected instruction bytes: {bytes:02X?}")),
                    Err(_) => Ok(()),
                };
            }
        };
        let bytes = assemble_architecture(text, architecture, 0x1000)?;
        (bytes == expected)
            .then_some(())
            .ok_or_else(|| format!("Unexpected instruction bytes: {bytes:02X?}"))
    }

    /*
    This test starts simultaneous assembly requests before any test-local request completes.
    The process lock serializes native loading and assembly for every supported engine.
    */
    #[test]
    fn concurrent_first_use_is_serialized() {
        const THREADS: usize = 8;
        const ROUNDS: usize = 8;
        let barrier = Arc::new(Barrier::new(THREADS));
        let (send, receive) = mpsc::channel();
        let handles = (0..THREADS)
            .map(|thread| {
                let barrier = Arc::clone(&barrier);
                let send = send.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let result = (0..ROUNDS).try_for_each(|round| known_result(thread + round));
                    let _ = send.send(result);
                })
            })
            .collect::<Vec<_>>();
        drop(send);
        for _ in 0..THREADS {
            receive
                .recv_timeout(Duration::from_secs(15))
                .expect("Concurrent assembly did not finish")
                .unwrap();
        }
        for handle in handles {
            handle.join().unwrap();
        }
    }

    /*
    This test preserves established x86 vectors and input errors.
    It also checks direct invalid x86 variants and unsupported ARM64 assembly.
    */
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
        assert!(assemble_architecture("nop", Architecture::X86(8), 0).is_err());
        assert_eq!(
            assemble_architecture("nop", Architecture::Arm64, 0).unwrap_err(),
            "ARM64 assembly is unsupported."
        );
    }

    /*
    This test checks independent ARM and Thumb encodings at their selected runtime addresses.
    Unaligned MOV requests remain accepted and produce the same native bytes.
    */
    #[test]
    fn arm_and_thumb_vectors_use_the_selected_runtime_address() {
        assert_eq!(
            assemble_architecture("mov r0, r0", Architecture::Arm, 0x1000).unwrap(),
            [0x00, 0x00, 0xa0, 0xe1]
        );
        assert_eq!(
            assemble_architecture("mov r0, r0", Architecture::Arm, 0x1001).unwrap(),
            [0x00, 0x00, 0xa0, 0xe1]
        );
        assert_eq!(
            assemble_architecture("b #0x1008", Architecture::Arm, 0x1000).unwrap(),
            [0x00, 0x00, 0x00, 0xea]
        );
        assert_eq!(
            assemble_architecture("bl #0x1010", Architecture::Arm, 0x1000).unwrap(),
            [0x02, 0x00, 0x00, 0xeb]
        );
        assert_eq!(
            assemble_architecture("movs r0, #1", Architecture::Thumb, 0x1000).unwrap(),
            [0x01, 0x20]
        );
        assert_eq!(
            assemble_architecture("movs r0, #1", Architecture::Thumb, 0x1001).unwrap(),
            [0x01, 0x20]
        );
        assert_eq!(
            assemble_architecture("b #0x1000", Architecture::Thumb, 0x1000).unwrap(),
            [0xfe, 0xe7]
        );
        assert_eq!(
            assemble_architecture("bl #0x1010", Architecture::Thumb, 0x1000).unwrap(),
            [0x00, 0xf0, 0x06, 0xf8]
        );
        for architecture in [Architecture::Arm, Architecture::Thumb] {
            assert!(assemble_architecture("unknown_opcode", architecture, 0x1000).is_err());
            assert!(assemble_architecture("nop; nop", architecture, 0x1000).is_err());
        }
    }

    /*
    This test decodes each assembled ARM-family vector through the selected Capstone engine.
    The independent expected size and mnemonic confirm the complete engine round trip.
    */
    #[test]
    fn arm_and_thumb_round_trip_through_capstone() {
        for (architecture, source, size, mnemonic) in [
            (Architecture::Arm, "mov r0, r0", 4, "mov"),
            (Architecture::Arm, "bl #0x1010", 4, "bl"),
            (Architecture::Thumb, "movs r0, #1", 2, "movs"),
            (Architecture::Thumb, "bl #0x1010", 4, "bl"),
        ] {
            let bytes = assemble_architecture(source, architecture, 0x1000).unwrap();
            let decoder = crate::decoder::Decoder::with_architecture(
                architecture,
                crate::decoder::Syntax::Intel,
                false,
            )
            .unwrap();
            let instruction = decoder.decode(&bytes, 0, 0x1000).unwrap();
            assert_eq!(instruction.size, size);
            assert!(
                instruction.text.starts_with(mnemonic),
                "{}",
                instruction.text
            );
        }
    }
}
