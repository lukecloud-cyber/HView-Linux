use crate::native::Library;
use std::ffi::c_void;
use std::fmt::Write;

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

pub struct Decoder {
    _library: Library,
    handle: usize,
    disasm: Disasm,
    free: Free,
    close: Close,
    bits: u32,
    syntax: Syntax,
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
            bits,
            syntax,
        })
    }

    pub fn bits(&self) -> u32 {
        self.bits
    }

    pub fn syntax(&self) -> Syntax {
        self.syntax
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
            Err(format!(
                "Invalid or incomplete x86 instruction at offset {offset:X}."
            ))
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
                let operands = text(&instruction.operands);
                let text = if operands.is_empty() {
                    mnemonic
                } else {
                    format!("{mnemonic:<13}{operands}")
                };
                Ok(Instruction { size, hex, text })
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
}
