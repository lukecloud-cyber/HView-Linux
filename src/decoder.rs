use crate::native::Library;
use std::ffi::{CStr, c_char, c_void};
use std::fmt::Write;

// Pinned Zydis 1ba75ae marks at least one definition for each name as protected-only.
const REAL16_PROTECTED: [&str; 41] = [
    "arpl",
    "clgi",
    "clrssbsy",
    "encls",
    "enclu",
    "enclv",
    "getsec",
    "incsspd",
    "invept",
    "invlpga",
    "invvpid",
    "lar",
    "lldt",
    "lsl",
    "ltr",
    "rstorssp",
    "saveprevssp",
    "setssbsy",
    "skinit",
    "sldt",
    "stgi",
    "str",
    "sysenter",
    "sysexit",
    "sysret",
    "verr",
    "verw",
    "vmclear",
    "vmlaunch",
    "vmload",
    "vmptrld",
    "vmptrst",
    "vmread",
    "vmresume",
    "vmrun",
    "vmsave",
    "vmwrite",
    "vmxoff",
    "vmxon",
    "wrssd",
    "wrussd",
];

const RELATIVE_BRANCHES: &[&str] = &[
    "call", "ja", "jae", "jb", "jbe", "jc", "jcxz", "je", "jecxz", "jg", "jge", "jl", "jle", "jmp",
    "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl", "jnle", "jno", "jnp", "jns",
    "jnz", "jo", "jp", "jpe", "jpo", "js", "jz", "loop", "loope", "loopne", "xbegin",
];

#[derive(Debug)]
pub struct Instruction {
    pub size: usize,
    pub hex: String,
    pub text: String,
}

#[repr(C)]
struct CsInstruction {
    id: u32,
    address: u64,
    size: u16,
    bytes: [u8; 24],
    mnemonic: [u8; 32],
    operands: [u8; 160],
    detail: *mut c_void,
}

fn text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

type Disasm =
    unsafe extern "C" fn(usize, *const u8, usize, u64, usize, *mut *mut CsInstruction) -> usize;
type Free = unsafe extern "C" fn(*mut CsInstruction, usize);
type Close = unsafe extern "C" fn(*mut usize) -> i32;
type InstructionName = unsafe extern "C" fn(usize, u32) -> *const c_char;

pub struct Decoder {
    _library: Library,
    handle: usize,
    disasm: Disasm,
    free: Free,
    close: Close,
    instruction_name: InstructionName,
    bits: u32,
    syntax: Syntax,
    real_mode: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Syntax {
    #[default]
    Intel,
    Att,
}

impl Decoder {
    pub fn new(bits: u32) -> Result<Self, String> {
        Self::with_syntax(bits, Syntax::Intel)
    }

    pub fn with_syntax(bits: u32, syntax: Syntax) -> Result<Self, String> {
        Self::with_mode(bits, syntax, false)
    }

    pub fn with_mode(bits: u32, syntax: Syntax, real_mode: bool) -> Result<Self, String> {
        if real_mode && bits != 16 {
            return Err("Real16 requires a 16-bit decoder.".into());
        }
        let mode = match bits {
            16 => 2,
            32 => 4,
            64 => 8,
            _ => return Err("The decoder supports only 16, 32, or 64 bits.".into()),
        };
        let library = Library::open("libcapstone.so")?;
        macro_rules! symbol {
            ($name:literal, $kind:ty) => {{
                let address = library.symbol(concat!($name, "\0").as_bytes())?;
                unsafe { std::mem::transmute::<*mut c_void, $kind>(address) }
            }};
        }
        let version = symbol!(
            "cs_version",
            unsafe extern "C" fn(*mut i32, *mut i32) -> u32
        );
        let open = symbol!("cs_open", unsafe extern "C" fn(u32, u32, *mut usize) -> i32);
        let disasm = symbol!("cs_disasm", Disasm);
        let free = symbol!("cs_free", Free);
        let close = symbol!("cs_close", Close);
        let instruction_name = symbol!("cs_insn_name", InstructionName);
        let option = symbol!("cs_option", unsafe extern "C" fn(usize, i32, usize) -> i32);
        let mut major = 0;
        let mut minor = 0;
        unsafe {
            version(&mut major, &mut minor);
        }
        if major != 5 {
            return Err(format!(
                "Unsupported Capstone API version {major}.{minor}. Install version 5."
            ));
        }
        let mut handle = 0;
        let status = unsafe { open(3, mode, &mut handle) };
        if status != 0 {
            return Err(format!(
                "Cannot initialize the x86 decoder: Capstone error {status}."
            ));
        }
        let syntax_value = match syntax {
            Syntax::Intel => 1,
            Syntax::Att => 2,
        };
        let status = unsafe { option(handle, 1, syntax_value) };
        if status != 0 {
            unsafe {
                close(&mut handle);
            }
            return Err(format!(
                "Cannot select the disassembly syntax: Capstone error {status}."
            ));
        }
        Ok(Self {
            _library: library,
            handle,
            disasm,
            free,
            close,
            instruction_name,
            bits,
            syntax,
            real_mode,
        })
    }

    pub fn bits(&self) -> u32 {
        self.bits
    }

    pub fn syntax(&self) -> Syntax {
        self.syntax
    }

    pub fn real_mode(&self) -> bool {
        self.real_mode
    }

    pub fn decode(&self, data: &[u8], offset: u64, address: u64) -> Result<Instruction, String> {
        let start = usize::try_from(offset).map_err(|_| "The offset exceeds the address range.")?;
        let bytes = data
            .get(start..)
            .filter(|bytes| !bytes.is_empty())
            .ok_or("The decoder reached the end of the file.")?;
        let mut instruction = std::ptr::null_mut();
        let count = unsafe {
            (self.disasm)(
                self.handle,
                bytes.as_ptr(),
                bytes.len().min(15),
                address,
                1,
                &mut instruction,
            )
        };
        let result = if count != 1 || instruction.is_null() {
            Err(invalid_instruction(offset))
        } else {
            let instruction = unsafe { &*instruction };
            let size = instruction.size as usize;
            if size == 0 || size > bytes.len().min(15) {
                Err("The decoder returned an invalid instruction size.".into())
            } else {
                let mut hex = String::with_capacity(size * 2);
                for byte in &bytes[..size] {
                    write!(hex, "{byte:02X}").unwrap();
                }
                let mnemonic = text(&instruction.mnemonic);
                let mut operands = text(&instruction.operands);
                let name = unsafe { (self.instruction_name)(self.handle, instruction.id) };
                let canonical = if name.is_null() {
                    mnemonic.as_str()
                } else {
                    unsafe { CStr::from_ptr(name) }
                        .to_str()
                        .unwrap_or(&mnemonic)
                };
                if self.real_mode
                    && (real16_protected(bytes, size, canonical)
                        || real16_vector(bytes, size, canonical))
                {
                    Err(invalid_instruction(offset))
                } else {
                    if self.real_mode
                        && RELATIVE_BRANCHES.contains(&canonical)
                        && let Some(target) = number(&operands)
                    {
                        operands = format!("0x{:x}", target & 0xffff);
                    }
                    let text = if operands.is_empty() {
                        mnemonic
                    } else {
                        format!("{mnemonic:<13}{operands}")
                    };
                    Ok(Instruction { size, hex, text })
                }
            }
        };
        unsafe {
            if !instruction.is_null() {
                (self.free)(instruction, count);
            }
        }
        result
    }
}

fn invalid_instruction(offset: u64) -> String {
    format!("Invalid or incomplete x86 instruction at offset {offset:X}.")
}

fn number(text: &str) -> Option<u64> {
    let text = text.trim().strip_prefix('$').unwrap_or(text.trim());
    text.strip_prefix("0x")
        .map(|digits| u64::from_str_radix(digits, 16))
        .unwrap_or_else(|| text.parse())
        .ok()
}

fn real16_vector(bytes: &[u8], size: usize, mnemonic: &str) -> bool {
    let opcode = bytes[..size].iter().copied().find(|byte| {
        !matches!(
            byte,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3
        )
    });
    match (opcode, mnemonic) {
        (Some(0xc4), name) => name != "les",
        (Some(0xc5), name) => name != "lds",
        (Some(0x62), name) => name != "bound",
        (Some(0x8f), name) => name != "pop",
        _ => false,
    }
}

fn real16_protected(bytes: &[u8], size: usize, mnemonic: &str) -> bool {
    // Zydis permits the register VMWRITE definition and rejects its memory definition in Real16.
    if mnemonic == "vmwrite"
        && bytes
            .get(..size)
            .and_then(|bytes| bytes.last())
            .is_some_and(|byte| byte & 0xc0 == 0xc0)
    {
        return false;
    }
    REAL16_PROTECTED.contains(&mnemonic)
}

impl Drop for Decoder {
    fn drop(&mut self) {
        unsafe {
            (self.close)(&mut self.handle);
        }
    }
}

pub fn decode(data: &[u8], offset: u64, bits: u32, address: u64) -> Result<Instruction, String> {
    Decoder::new(bits)?.decode(data, offset, address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_mode_boundaries() {
        assert_eq!(std::mem::size_of::<CsInstruction>(), 248);
        assert_eq!(std::mem::offset_of!(CsInstruction, mnemonic), 42);
        assert_eq!(std::mem::offset_of!(CsInstruction, detail), 240);
        let decoder16 = Decoder::new(16).unwrap();
        let instruction = decoder16.decode(&[0, 1], 0, 0).unwrap();
        assert_eq!((instruction.size, instruction.hex.as_str()), (2, "0001"));
        assert!(instruction.text.starts_with("add          "));
        assert!(instruction.text.contains("bx + di"));
        let bytes = [0x60, 0xe9, 0x3d, 4, 0, 0];
        let decoder32 = Decoder::new(32).unwrap();
        assert_eq!(decoder32.decode(&bytes, 0, 0x478001).unwrap().size, 1);
        let branch = decoder32.decode(&bytes, 1, 0x478002).unwrap();
        assert_eq!(branch.size, 5);
        assert!(branch.text.contains("0x478444"));
        let decoder64 = Decoder::new(64).unwrap();
        let wide = decoder64.decode(&[0x48, 0x89, 0xd8], 0, 0).unwrap();
        assert_eq!(wide.size, 3);
        assert!(wide.text.contains("rax, rbx"));
        assert_eq!(decoder16.decode(&[0x48, 0x89, 0xd8], 0, 0).unwrap().size, 1);
        assert!(decoder32.decode(&[0x0f], 0, 0).is_err());
        assert_eq!(decoder32.decode(&[0x90], 0, 0).unwrap().size, 1);
        assert!(decoder32.decode(&[], 0, 0).is_err());
        assert!(decoder32.decode(&[0x90], u64::MAX, 0).is_err());
        assert!(Decoder::new(8).is_err());
        assert!(decoder32.decode(&[0x66; 16], 0, 0).is_err());
        let att = Decoder::with_syntax(32, Syntax::Att).unwrap();
        assert!(att.decode(&[0x89, 0xd8], 0, 0).unwrap().text.contains("%"));
    }

    #[test]
    fn real16_matches_the_pinned_oracle_policy() {
        assert_eq!(REAL16_PROTECTED.len(), 41);
        assert!(REAL16_PROTECTED.windows(2).all(|pair| pair[0] < pair[1]));
        let real = Decoder::with_mode(16, Syntax::Intel, true).unwrap();
        let att = Decoder::with_mode(16, Syntax::Att, true).unwrap();
        assert!(real.real_mode());
        for (bytes, size, text) in [
            (&[0x90][..], 1, "nop"),
            (&[0x89, 0xd8], 2, "ax, bx"),
            (&[0x66, 0x89, 0xd8], 3, "eax, ebx"),
            (&[0x8b, 0x00], 2, "[bx + si]"),
            (&[0x67, 0x8b, 0x00], 3, "[eax]"),
            (&[0x26, 0x8b, 0x00], 3, "es:"),
            (&[0x0f, 0x20, 0xc0], 3, "eax, cr0"),
            (&[0xea, 0x34, 0x12, 0x78, 0x56], 5, "0x5678:0x1234"),
            (
                &[0x66, 0xea, 0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a],
                8,
                "0x9abc:0x12345678",
            ),
        ] {
            let instruction = real.decode(bytes, 0, 0).unwrap();
            assert_eq!(instruction.size, size);
            assert!(instruction.text.contains(text), "{}", instruction.text);
        }
        assert!(
            att.decode(&[0x89, 0xd8], 0, 0)
                .unwrap()
                .text
                .contains("%bx, %ax")
        );
        for decoder in [&real, &att] {
            for bytes in [
                &[0x63, 0xc0][..],
                &[0x0f, 0x00, 0xc0],
                &[0x0f, 0x00, 0xd0],
                &[0x0f, 0x02, 0xc0],
                &[0x0f, 0x34],
                &[0xc5, 0xf8, 0x77],
                &[0xc4, 0xe1, 0x78, 0x77],
                &[0x62, 0xf1, 0x7c, 0x48, 0x58, 0xc0],
                &[0x8f, 0xe9, 0x78, 0x90, 0xc0],
                &[],
                &[0x66],
                &[0x0f],
                &[0xc5],
                &[0xea, 0x34],
            ] {
                assert!(decoder.decode(bytes, 0, 0).is_err());
            }
            for bytes in [&[0x0f, 0x79, 0xc0][..], &[0x67, 0x0f, 0x79, 0xc0]] {
                assert!(
                    decoder
                        .decode(bytes, 0, 0)
                        .unwrap()
                        .text
                        .contains("vmwrite")
                );
            }
            for bytes in [&[0x0f, 0x79, 0x00][..], &[0x67, 0x0f, 0x79, 0x00]] {
                assert!(decoder.decode(bytes, 0, 0).is_err());
            }
        }
        for (bytes, name) in [
            (&[0xc4, 0x00][..], "les"),
            (&[0xc5, 0x00], "lds"),
            (&[0x62, 0x00], "bound"),
            (&[0x8f, 0x00], "pop"),
        ] {
            let instruction = real.decode(bytes, 0, 0).unwrap();
            assert_eq!(instruction.size, 2);
            assert!(instruction.text.starts_with(name));
        }
        assert!(Decoder::with_mode(32, Syntax::Intel, true).is_err());
    }

    #[test]
    fn real16_wraps_only_relative_targets() {
        let real = Decoder::with_mode(16, Syntax::Intel, true).unwrap();
        let att = Decoder::with_mode(16, Syntax::Att, true).unwrap();
        for (bytes, advance) in [
            (&[0xeb, 0xfe][..], 0u64),
            (&[0xe9, 0xfe, 0xff], 1),
            (&[0x66, 0xe9, 0xfc, 0xff, 0xff, 0xff], 2),
            (&[0x67, 0xe2, 0xfe], 1),
            (&[0xc7, 0xf8, 0x00, 0x00], 4),
        ] {
            for address in [0u64, 0xffff, 0x10000] {
                let target = format!("0x{:x}", address.wrapping_add(advance) & 0xffff);
                for decoder in [&real, &att] {
                    assert!(
                        decoder
                            .decode(bytes, 0, address)
                            .unwrap()
                            .text
                            .ends_with(&target)
                    );
                }
            }
        }
        let far = real
            .decode(&[0xea, 0x34, 0x12, 0x78, 0x56], 0, 0x10000)
            .unwrap();
        assert!(far.text.ends_with("0x5678:0x1234"));
        for (bytes, target) in [
            (&[0x66, 0xeb, 0xfe][..], "0x1"),
            (&[0xf2, 0xeb, 0xfe], "0x1"),
            (&[0x2e, 0xeb, 0xfe], "0x1"),
            (&[0x67, 0xe3, 0xfe], "0x1"),
            (&[0x66, 0xe8, 0xfc, 0xff, 0xff, 0xff], "0x2"),
            (&[0x66, 0x0f, 0x84, 0xff, 0xff, 0xff, 0xff], "0x6"),
            (&[0x66, 0xc7, 0xf8, 0, 0, 0, 0], "0x7"),
        ] {
            for decoder in [&real, &att] {
                assert!(
                    decoder
                        .decode(bytes, 0, 0x10000)
                        .unwrap()
                        .text
                        .ends_with(target)
                );
            }
        }
    }
}
