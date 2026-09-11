/*
This module decodes one x86 or ARM-family instruction through the pinned Capstone interface.
Typed internal results keep invalid source bytes separate from engine and interface errors.
*/
use crate::format::Architecture;
use crate::native::Library;
use std::ffi::{CStr, c_char, c_void};
use std::fmt::Write;

/*
These constants match the pinned Capstone 5.0.9 architecture, mode, option, and branch-group values.
All selected native modes keep little-endian instruction bytes.
*/
const CS_ARCH_ARM: u32 = 0;
const CS_ARCH_ARM64: u32 = 1;
const CS_ARCH_X86: u32 = 3;
const CS_MODE_ARM: u32 = 0;
const CS_MODE_X86_16: u32 = 2;
const CS_MODE_X86_32: u32 = 4;
const CS_MODE_X86_64: u32 = 8;
const CS_MODE_THUMB: u32 = 0x10;
const CS_OPT_SYNTAX: i32 = 1;
const CS_OPT_DETAIL: i32 = 2;
const CS_OPT_OFF: usize = 0;
const CS_OPT_SYNTAX_INTEL: usize = 1;
const CS_OPT_SYNTAX_ATT: usize = 2;
const CS_OPT_ON: usize = 3;
const CS_GRP_BRANCH_RELATIVE: u32 = 7;

/*
Each name has at least one protected-only definition in the pinned Zydis reference.
Some opcode forms have accepted exceptions that later checks preserve.
The decoder applies the table after Capstone returns a structurally valid instruction.
*/
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

/*
These canonical names identify relative targets that wrap at 16 bits in Real16 mode.
Capstone syntax changes do not change the canonical instruction name.
*/
const RELATIVE_BRANCHES: &[&str] = &[
    "call", "ja", "jae", "jb", "jbe", "jc", "jcxz", "je", "jecxz", "jg", "jge", "jl", "jle", "jmp",
    "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl", "jnle", "jno", "jnp", "jns",
    "jnz", "jo", "jp", "jpe", "jpo", "js", "jz", "loop", "loope", "loopne", "xbegin",
];

/*
Instruction contains the byte length and display strings for one accepted decode.
Code rendering and assembly preview consume these fields without native pointers.
*/
#[derive(Debug)]
pub struct Instruction {
    pub size: usize,
    pub hex: String,
    pub text: String,
}

/*
CsInstruction matches the Capstone 5.0.9 ABI layout used by the loaded library.
Tests verify the critical size and field offsets before native decoding.
*/
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

/*
This helper converts one fixed native text buffer through its first NUL byte.
Lossy conversion prevents invalid native text from violating Rust string rules.
*/
fn text(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/*
These function types describe the loaded Capstone ABI.
Decoder stores the functions with its handle so repeated instructions reuse one engine.
*/
type Disasm =
    unsafe extern "C" fn(usize, *const u8, usize, u64, usize, *mut *mut CsInstruction) -> usize;
type Free = unsafe extern "C" fn(*mut CsInstruction, usize);
type Close = unsafe extern "C" fn(*mut usize) -> i32;
type InstructionName = unsafe extern "C" fn(usize, u32) -> *const c_char;
type SetOption = unsafe extern "C" fn(usize, i32, usize) -> i32;
type InGroup = unsafe extern "C" fn(usize, *const CsInstruction, u32) -> bool;
type Error = unsafe extern "C" fn(usize) -> i32;

/*
These test-only functions produce one native decoder error for application-path checks.
They do not exist in production builds and do not add a production fault switch.
*/
#[cfg(test)]
unsafe extern "C" fn forced_error_disasm(
    _handle: usize,
    _code: *const u8,
    _size: usize,
    _address: u64,
    _count: usize,
    output: *mut *mut CsInstruction,
) -> usize {
    unsafe { *output = std::ptr::null_mut() };
    0
}

#[cfg(test)]
unsafe extern "C" fn forced_error_status(_handle: usize) -> i32 {
    17
}

/*
DecodeOutcome identifies successful decoding and ordinary invalid source bytes.
The Result error channel contains engine, input-range, and native-interface errors.
*/
enum DecodeOutcome {
    Instruction(Instruction),
    NoInstruction(Vec<u8>),
}

/*
Decoder owns one loaded library, one native handle, and its complete cache identity.
Drop closes the handle after all decoding and detail operations finish.
*/
pub struct Decoder {
    _library: Library,
    handle: usize,
    disasm: Disasm,
    free: Free,
    close: Close,
    instruction_name: InstructionName,
    set_option: SetOption,
    in_group: InGroup,
    error: Error,
    architecture: Architecture,
    syntax: Syntax,
    real_mode: bool,
}

/*
Syntax selects Intel or AT&T output for x86 decoding.
Intel remains the default and the x86 assembler always accepts Intel input.
ARM-family decoders retain this cache property without applying the x86 option.
*/
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Syntax {
    #[default]
    Intel,
    Att,
}

impl Decoder {
    /*
    These width wrappers preserve the existing x86 API for narrow callers.
    Each wrapper constructs a validated Architecture before it enters the engine boundary.
    */
    pub fn new(bits: u32) -> Result<Self, String> {
        Self::with_syntax(bits, Syntax::Intel)
    }

    pub fn with_syntax(bits: u32, syntax: Syntax) -> Result<Self, String> {
        Self::with_mode(bits, syntax, false)
    }

    pub fn with_mode(bits: u32, syntax: Syntax, real_mode: bool) -> Result<Self, String> {
        let architecture = Architecture::x86(bits)
            .map_err(|_| "The decoder supports only 16, 32, or 64 bits.".to_owned())?;
        Self::with_architecture(architecture, syntax, real_mode)
    }

    /*
    This engine boundary validates x86 widths and selects each supported Capstone engine.
    Real16 remains valid only for the 16-bit x86 engine.
    */
    pub fn with_architecture(
        architecture: Architecture,
        syntax: Syntax,
        real_mode: bool,
    ) -> Result<Self, String> {
        if real_mode && architecture != Architecture::X86(16) {
            return Err("Real16 requires a 16-bit decoder.".into());
        }
        let (native_architecture, mode, name) = match architecture {
            Architecture::X86(16) => (CS_ARCH_X86, CS_MODE_X86_16, "x86"),
            Architecture::X86(32) => (CS_ARCH_X86, CS_MODE_X86_32, "x86"),
            Architecture::X86(64) => (CS_ARCH_X86, CS_MODE_X86_64, "x86"),
            Architecture::X86(_) => {
                return Err("The decoder supports only 16, 32, or 64 bits.".into());
            }
            Architecture::Arm => (CS_ARCH_ARM, CS_MODE_ARM, "ARM"),
            Architecture::Thumb => (CS_ARCH_ARM, CS_MODE_THUMB, "Thumb"),
            Architecture::Arm64 => (CS_ARCH_ARM64, CS_MODE_ARM, "ARM64"),
        };

        /*
        The native loader resolves the complete Capstone 5.0.9 interface.
        cs_errno lets later decoding classify a zero result without masking engine failures.
        */
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
        let set_option = symbol!("cs_option", SetOption);
        let in_group = symbol!("cs_insn_group", InGroup);
        let error = symbol!("cs_errno", Error);
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
        let status = unsafe { open(native_architecture, mode, &mut handle) };
        if status != 0 {
            return Err(format!(
                "Cannot initialize the {name} decoder: Capstone error {status}."
            ));
        }
        /*
        X86 applies the requested display syntax through Capstone.
        ARM-family engines retain the setting only as part of the cache identity.
        */
        let status = if matches!(architecture, Architecture::X86(_)) {
            let syntax_value = match syntax {
                Syntax::Intel => CS_OPT_SYNTAX_INTEL,
                Syntax::Att => CS_OPT_SYNTAX_ATT,
            };
            unsafe { set_option(handle, CS_OPT_SYNTAX, syntax_value) }
        } else {
            0
        };
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
            set_option,
            in_group,
            error,
            architecture,
            syntax,
            real_mode,
        })
    }

    /*
    These queries expose the complete effective decoder properties for cache matching.
    Test-only queries and injection support verify reuse and error routing without production switches.
    */
    #[allow(
        dead_code,
        reason = "The x86 width query remains for compatibility callers."
    )]
    pub fn bits(&self) -> u32 {
        self.architecture.bits()
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    #[cfg(test)]
    pub fn native_handle(&self) -> usize {
        self.handle
    }

    #[cfg(test)]
    pub fn force_decode_error(&mut self) {
        self.disasm = forced_error_disasm;
        self.error = forced_error_status;
    }

    pub fn syntax(&self) -> Syntax {
        self.syntax
    }

    pub fn real_mode(&self) -> bool {
        self.real_mode
    }

    /*
    This internal decoder limits input to the selected architecture maximum.
    ARM-family input must fit through its final runtime byte without overflow.
    Only a zero count, a null pointer, and CS_ERR_OK identify ordinary invalid source bytes.
    */
    fn decode_one(&self, data: &[u8], offset: u64, address: u64) -> Result<DecodeOutcome, String> {
        /*
        The input section converts the file offset and selects one bounded native slice.
        EOF and an unrepresentable Rust index stop before the engine call.
        */
        let start = usize::try_from(offset).map_err(|_| "The offset exceeds the address range.")?;
        let bytes = data
            .get(start..)
            .filter(|bytes| !bytes.is_empty())
            .ok_or("The decoder reached the end of the file.")?;
        let input_len = bytes.len().min(self.architecture.max_instruction_bytes());
        if !matches!(self.architecture, Architecture::X86(_)) {
            address
                .checked_add(input_len as u64 - 1)
                .ok_or("The ARM instruction exceeds the runtime address range.")?;
        }
        /*
        The native section requests one instruction and classifies the result tuple.
        A normal invalid byte requires the exact zero, null, and CS_ERR_OK combination.
        */
        let mut instruction = std::ptr::null_mut();
        let count = unsafe {
            (self.disasm)(
                self.handle,
                bytes.as_ptr(),
                input_len,
                address,
                1,
                &mut instruction,
            )
        };
        let result = if count == 0 {
            let status = unsafe { (self.error)(self.handle) };
            if status != 0 {
                Err(format!(
                    "Capstone decoding failed at offset {offset:X}: error {status}."
                ))
            } else if instruction.is_null() {
                let size = input_len.min(self.architecture.alignment() as usize);
                Ok(DecodeOutcome::NoInstruction(bytes[..size].to_vec()))
            } else {
                Err("The decoder returned an invalid instruction pointer.".into())
            }
        } else if count != 1 || instruction.is_null() {
            Err("The decoder returned an invalid instruction count.".into())
        } else {
            /*
            The success section validates the architecture size before it reads display fields.
            Real16 policy can convert a valid Capstone decode into ordinary invalid input.
            */
            let instruction = unsafe { &*instruction };
            let size = instruction.size as usize;
            if !self.architecture.valid_instruction_bytes(size) || size > input_len {
                Err("The decoder returned an invalid instruction size.".into())
            } else {
                /*
                The interpretation section builds owned display text and applies Real16 policy.
                Relative Real16 targets wrap after the canonical instruction name passes policy.
                */
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
                    let size = input_len.min(self.architecture.alignment() as usize);
                    Ok(DecodeOutcome::NoInstruction(bytes[..size].to_vec()))
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
                    Ok(DecodeOutcome::Instruction(Instruction { size, hex, text }))
                }
            }
        };
        /*
        The cleanup section releases every nonnull native result after classification.
        The Rust result contains no borrowed native data.
        */
        unsafe {
            if !instruction.is_null() {
                (self.free)(instruction, count);
            }
        }
        result
    }

    /*
    Strict decoding converts an ordinary invalid-byte result into its architecture-specific error.
    Engine and interface errors pass through unchanged.
    */
    pub fn decode(&self, data: &[u8], offset: u64, address: u64) -> Result<Instruction, String> {
        match self.decode_one(data, offset, address)? {
            DecodeOutcome::Instruction(instruction) => Ok(instruction),
            DecodeOutcome::NoInstruction(_) => Err(invalid_instruction(self.architecture, offset)),
        }
    }

    /*
    Optional decoding converts only ordinary invalid input into one visible architecture unit.
    A short source tail can produce a smaller final data unit.
    The caller can use this result without catching unrelated decoder errors.
    */
    pub fn decode_or_byte(
        &self,
        data: &[u8],
        offset: u64,
        address: u64,
    ) -> Result<Instruction, String> {
        match self.decode_one(data, offset, address)? {
            DecodeOutcome::Instruction(instruction) => Ok(instruction),
            DecodeOutcome::NoInstruction(bytes) => {
                let mut hex = String::with_capacity(bytes.len() * 2);
                for byte in &bytes {
                    write!(hex, "{byte:02X}").unwrap();
                }
                let text = if matches!(self.architecture, Architecture::X86(_)) {
                    format!("db {hex}")
                } else {
                    let operands = bytes
                        .iter()
                        .map(|byte| format!("0x{byte:02X}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("db           {operands}")
                };
                Ok(Instruction {
                    size: bytes.len(),
                    hex,
                    text,
                })
            }
        }
    }

    /*
    Direct-target decoding validates ARM-family address range and enables Capstone detail.
    The final option change restores the reusable cached decoder state.
    */
    pub fn direct_target(&self, data: &[u8], address: u64) -> Result<Option<u64>, String> {
        let input_len = data.len().min(self.architecture.max_instruction_bytes());
        if !matches!(self.architecture, Architecture::X86(_)) && input_len != 0 {
            address
                .checked_add(input_len as u64 - 1)
                .ok_or("The ARM instruction exceeds the runtime address range.")?;
        }
        let status = unsafe { (self.set_option)(self.handle, CS_OPT_DETAIL, CS_OPT_ON) };
        if status != 0 {
            unsafe {
                (self.set_option)(self.handle, CS_OPT_DETAIL, CS_OPT_OFF);
            }
            return Err(format!(
                "Cannot enable Capstone detail: Capstone error {status}."
            ));
        }

        let result = self.direct_target_with_detail(data, address);
        let status = unsafe { (self.set_option)(self.handle, CS_OPT_DETAIL, CS_OPT_OFF) };
        if status != 0 {
            return Err(format!(
                "Cannot disable Capstone detail: Capstone error {status}."
            ));
        }
        result
    }

    fn direct_target_with_detail(&self, data: &[u8], address: u64) -> Result<Option<u64>, String> {
        /*
        The input section refuses EOF before it requests one bounded instruction.
        The enabled detail option supplies branch-group membership.
        */
        if data.is_empty() {
            return Err("The decoder reached the end of the file.".into());
        }
        let mut instruction = std::ptr::null_mut();
        let count = unsafe {
            (self.disasm)(
                self.handle,
                data.as_ptr(),
                data.len().min(self.architecture.max_instruction_bytes()),
                address,
                1,
                &mut instruction,
            )
        };
        /*
        The result section applies the same native error classification as normal decoding.
        A valid non-branch returns no target, while direct branches return a parsed address.
        */
        let result = if count == 0 {
            let status = unsafe { (self.error)(self.handle) };
            if status != 0 {
                Err(format!(
                    "Capstone decoding failed at address {address:X}: error {status}."
                ))
            } else if instruction.is_null() {
                Err(format!(
                    "Invalid or incomplete {} instruction at address {address:X}.",
                    architecture_name(self.architecture)
                ))
            } else {
                Err("The decoder returned an invalid instruction pointer.".into())
            }
        } else if count != 1 || instruction.is_null() {
            Err("The decoder returned an invalid instruction count.".into())
        } else {
            let instruction_ref = unsafe { &*instruction };
            let size = instruction_ref.size as usize;
            if !self.architecture.valid_instruction_bytes(size)
                || size > data.len().min(self.architecture.max_instruction_bytes())
            {
                Err("The decoder returned an invalid instruction size.".into())
            } else {
                /*
                The target section applies Real16 policy and checks Capstone branch-group membership.
                ARM-family parsing uses the final immediate, while BLX and indirect transfers remain targetless.
                */
                let mnemonic = text(&instruction_ref.mnemonic);
                let name = unsafe { (self.instruction_name)(self.handle, instruction_ref.id) };
                let canonical = if name.is_null() {
                    mnemonic.as_str()
                } else {
                    unsafe { CStr::from_ptr(name) }
                        .to_str()
                        .unwrap_or(&mnemonic)
                };
                if self.real_mode
                    && (real16_protected(data, size, canonical)
                        || real16_vector(data, size, canonical))
                {
                    Err(format!(
                        "Invalid or incomplete x86 instruction at address {address:X}."
                    ))
                } else if mnemonic.eq_ignore_ascii_case("blx")
                    || !unsafe {
                        (self.in_group)(self.handle, instruction_ref, CS_GRP_BRANCH_RELATIVE)
                    }
                {
                    Ok(None)
                } else {
                    let operands = text(&instruction_ref.operands);
                    let operand = if matches!(self.architecture, Architecture::X86(_)) {
                        operands.as_str()
                    } else {
                        operands.rsplit(',').next().unwrap_or("").trim()
                    };
                    let operand = operand.strip_prefix('#').unwrap_or(operand);
                    number(operand)
                        .map(|target| {
                            Some(if self.real_mode {
                                target & 0xffff
                            } else {
                                target
                            })
                        })
                        .ok_or_else(|| {
                            format!("Capstone returned an invalid direct target: {operand}.")
                        })
                }
            }
        };
        /*
        The cleanup section releases any native instruction before returning the target result.
        The outer method restores the detail option afterward.
        */
        unsafe {
            if !instruction.is_null() {
                (self.free)(instruction, count);
            }
        }
        result
    }
}

/*
These helpers format architecture errors, parse direct targets, and enforce Real16 policy.
Prefix removal keeps vector and protected-instruction checks independent from display syntax.
*/
fn architecture_name(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86(_) => "x86",
        Architecture::Arm => "ARM",
        Architecture::Thumb => "Thumb",
        Architecture::Arm64 => "ARM64",
    }
}

fn invalid_instruction(architecture: Architecture, offset: u64) -> String {
    format!(
        "Invalid or incomplete {} instruction at offset {offset:X}.",
        architecture_name(architecture)
    )
}

/*
This helper parses one Capstone direct target in Intel or AT&T output.
It accepts an optional AT&T dollar sign and hexadecimal or decimal digits.
*/
fn number(text: &str) -> Option<u64> {
    let text = text.trim().strip_prefix('$').unwrap_or(text.trim());
    text.strip_prefix("0x")
        .map(|digits| u64::from_str_radix(digits, 16))
        .unwrap_or_else(|| text.parse())
        .ok()
}

/*
This helper identifies VEX, EVEX, and XOP encodings that Real16 rejects.
The overlapping LES, LDS, BOUND, and POP opcode meanings remain accepted exceptions.
*/
fn real16_vector(bytes: &[u8], size: usize, mnemonic: &str) -> bool {
    let opcode = after_prefixes(bytes, size).first().copied();
    match (opcode, mnemonic) {
        (Some(0xc4), name) => name != "les",
        (Some(0xc5), name) => name != "lds",
        (Some(0x62), name) => name != "bound",
        (Some(0x8f), name) => name != "pop",
        _ => false,
    }
}

fn real16_protected(bytes: &[u8], size: usize, mnemonic: &str) -> bool {
    /*
    Zydis permits the register VMWRITE definition and rejects its memory definition in Real16.
    The ModRM register form bypasses the general protected-only name table.
    */
    if mnemonic == "vmwrite"
        && after_prefixes(bytes, size)
            .get(..3)
            .is_some_and(|opcode| opcode.starts_with(&[0x0f, 0x79]) && opcode[2] & 0xc0 == 0xc0)
    {
        return false;
    }
    REAL16_PROTECTED.contains(&mnemonic)
}

/*
This helper removes only recognized legacy prefixes from one validated instruction range.
The caller supplies a size that passed architecture and input-length checks.
*/
fn after_prefixes(bytes: &[u8], size: usize) -> &[u8] {
    bytes
        .get(..size)
        .unwrap_or_default()
        .iter()
        .position(|byte| {
            !matches!(
                byte,
                0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3
            )
        })
        .map_or(&[], |start| &bytes[start..size])
}

/*
Decoder cleanup closes the native handle exactly once when Rust releases the cache entry.
The loaded Library remains alive until after this method finishes.
*/
impl Drop for Decoder {
    fn drop(&mut self) {
        unsafe {
            (self.close)(&mut self.handle);
        }
    }
}

/*
This compatibility function creates one validated x86 decoder for a narrow call.
Cached application paths use Decoder directly.
*/
pub fn decode(data: &[u8], offset: u64, bits: u32, address: u64) -> Result<Instruction, String> {
    Decoder::new(bits)?.decode(data, offset, address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

    /*
    These deterministic native stubs produce selected Capstone result combinations.
    The tests replace function pointers only inside one local Decoder instance.
    */
    static ERROR_STATUS: AtomicI32 = AtomicI32::new(0);
    static RETURN_KIND: AtomicUsize = AtomicUsize::new(0);
    static FREE_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn stub_disasm(
        _handle: usize,
        _code: *const u8,
        _size: usize,
        _address: u64,
        _count: usize,
        output: *mut *mut CsInstruction,
    ) -> usize {
        let kind = RETURN_KIND.load(Ordering::SeqCst);
        if kind == 0 {
            unsafe { *output = std::ptr::null_mut() };
            return 0;
        }
        if kind == 1 {
            unsafe { *output = std::ptr::null_mut() };
            return 1;
        }
        let mut instruction: Box<CsInstruction> = Box::new(unsafe { std::mem::zeroed() });
        instruction.size = match kind {
            3 => 16,
            5 => 2,
            _ => 1,
        };
        unsafe { *output = Box::into_raw(instruction) };
        match kind {
            2 => 2,
            4 => 0,
            _ => 1,
        }
    }

    unsafe extern "C" fn stub_error(_handle: usize) -> i32 {
        ERROR_STATUS.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn stub_free(instruction: *mut CsInstruction, _count: usize) {
        FREE_CALLS.fetch_add(1, Ordering::SeqCst);
        if !instruction.is_null() {
            drop(unsafe { Box::from_raw(instruction) });
        }
    }

    /*
    This test checks the native ABI, all x86 widths, syntax, limits, and invalid inputs.
    It provides the base contract for later Real16 and direct-target tests.
    */
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

    /*
    This test separates ordinary invalid input from engine errors and malformed native results.
    Every nonnull test result must reach the configured cleanup function.
    */
    #[test]
    fn decode_classifies_capstone_errors_and_malformed_returns() {
        let mut decoder = Decoder::new(32).unwrap();
        decoder.disasm = stub_disasm;
        decoder.error = stub_error;
        decoder.free = stub_free;

        RETURN_KIND.store(0, Ordering::SeqCst);
        ERROR_STATUS.store(0, Ordering::SeqCst);
        assert!(
            decoder
                .decode(&[0x0f], 0, 0)
                .unwrap_err()
                .contains("Invalid")
        );
        let byte = decoder.decode_or_byte(&[0x0f], 0, 0).unwrap();
        assert_eq!((byte.size, byte.text.as_str()), (1, "db 0F"));

        ERROR_STATUS.store(13, Ordering::SeqCst);
        let error = decoder.decode_or_byte(&[0x0f], 0, 0).unwrap_err();
        assert!(error.contains("error 13"));
        assert!(
            decoder
                .direct_target(&[0x0f], 0)
                .unwrap_err()
                .contains("error 13")
        );

        ERROR_STATUS.store(0, Ordering::SeqCst);
        RETURN_KIND.store(1, Ordering::SeqCst);
        assert_eq!(
            decoder.decode_or_byte(&[0x90], 0, 0).unwrap_err(),
            "The decoder returned an invalid instruction count."
        );
        RETURN_KIND.store(2, Ordering::SeqCst);
        FREE_CALLS.store(0, Ordering::SeqCst);
        assert_eq!(
            decoder.decode_or_byte(&[0x90], 0, 0).unwrap_err(),
            "The decoder returned an invalid instruction count."
        );
        assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 1);
        RETURN_KIND.store(4, Ordering::SeqCst);
        assert_eq!(
            decoder.decode_or_byte(&[0x90], 0, 0).unwrap_err(),
            "The decoder returned an invalid instruction pointer."
        );
        assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 2);
        RETURN_KIND.store(3, Ordering::SeqCst);
        assert_eq!(
            decoder.decode_or_byte(&[0x90; 16], 0, 0).unwrap_err(),
            "The decoder returned an invalid instruction size."
        );
        assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 3);
        RETURN_KIND.store(5, Ordering::SeqCst);
        assert_eq!(
            decoder.decode_or_byte(&[0x90], 0, 0).unwrap_err(),
            "The decoder returned an invalid instruction size."
        );
        assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 4);

        RETURN_KIND.store(2, Ordering::SeqCst);
        assert_eq!(
            decoder.direct_target(&[0x90], 0).unwrap_err(),
            "The decoder returned an invalid instruction count."
        );
        assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 5);

        assert!(decoder.decode_or_byte(&[], 0, 0).is_err());
        assert!(decoder.decode_or_byte(&[0x90], u64::MAX, 0).is_err());

        /*
        ARM and ARM64 reject a two-byte native result.
        Thumb rejects a one-byte native result, and each allocated result reaches cleanup.
        */
        for (architecture, kind, valid) in [
            (Architecture::Arm, 5, &[0x00, 0x00, 0xa0, 0xe1][..]),
            (Architecture::Arm64, 5, &[0x1f, 0x20, 0x03, 0xd5][..]),
            (Architecture::Thumb, 7, &[0x01, 0x20][..]),
        ] {
            let mut decoder =
                Decoder::with_architecture(architecture, Syntax::Intel, false).unwrap();
            let native_disasm = decoder.disasm;
            let native_error = decoder.error;
            let native_free = decoder.free;
            decoder.disasm = stub_disasm;
            decoder.error = stub_error;
            decoder.free = stub_free;
            RETURN_KIND.store(kind, Ordering::SeqCst);
            let before = FREE_CALLS.load(Ordering::SeqCst);
            assert_eq!(
                decoder.decode_or_byte(&[0; 4], 0, 0x1000).unwrap_err(),
                "The decoder returned an invalid instruction size."
            );
            assert_eq!(FREE_CALLS.load(Ordering::SeqCst), before + 1);
            assert_eq!(
                decoder.direct_target(&[0; 4], 0x1000).unwrap_err(),
                "The decoder returned an invalid instruction size."
            );
            assert_eq!(FREE_CALLS.load(Ordering::SeqCst), before + 2);
            decoder.disasm = native_disasm;
            decoder.error = native_error;
            decoder.free = native_free;
            assert_eq!(decoder.decode(valid, 0, 0x1000).unwrap().size, valid.len());
        }

        /*
        An injected engine error remains an error for every ARM family.
        No optional fallback converts the engine error into a data unit.
        */
        for (architecture, valid) in [
            (Architecture::Arm, &[0x00, 0x00, 0xa0, 0xe1][..]),
            (Architecture::Thumb, &[0x01, 0x20][..]),
            (Architecture::Arm64, &[0x1f, 0x20, 0x03, 0xd5][..]),
        ] {
            let mut decoder =
                Decoder::with_architecture(architecture, Syntax::Intel, false).unwrap();
            let native_disasm = decoder.disasm;
            let native_error = decoder.error;
            decoder.force_decode_error();
            assert!(
                decoder
                    .decode_or_byte(&[0; 4], 0, 0x1000)
                    .unwrap_err()
                    .contains("error 17")
            );
            assert!(
                decoder
                    .direct_target(&[0; 4], 0x1000)
                    .unwrap_err()
                    .contains("error 17")
            );
            decoder.disasm = native_disasm;
            decoder.error = native_error;
            assert_eq!(decoder.decode(valid, 0, 0x1000).unwrap().size, valid.len());
        }
    }

    /*
    This test checks native AVX encodings with independent mnemonic and size expectations.
    A valid instruction after invalid input confirms that the reusable handle remains usable.
    */
    #[test]
    fn native_avx_vectors_and_invalid_input_preserve_decoder_use() {
        let decoder = Decoder::new(64).unwrap();
        assert!(decoder.decode(&[0x0f], 0, 0).is_err());
        let vex = decoder.decode(&[0xc5, 0xf8, 0x77], 0, 0).unwrap();
        assert_eq!(vex.size, 3);
        assert!(vex.text.starts_with("vzeroupper"));
        let evex = decoder
            .decode(&[0x62, 0xf1, 0x7c, 0x48, 0x58, 0xc0], 0, 0)
            .unwrap();
        assert_eq!(evex.size, 6);
        assert!(evex.text.starts_with("vaddps"));
        assert_eq!(decoder.decode(&[0x90], 0, 0).unwrap().text, "nop");
    }

    /*
    This test checks architecture validation and native engine selection.
    Unsupported Real16 combinations fail before they can replace a usable decoder.
    */
    #[test]
    fn architecture_boundary_selects_supported_engines() {
        assert!(Decoder::with_architecture(Architecture::X86(8), Syntax::Intel, false).is_err());
        for architecture in [Architecture::Arm, Architecture::Thumb, Architecture::Arm64] {
            let decoder = Decoder::with_architecture(architecture, Syntax::Att, false).unwrap();
            assert_eq!(decoder.architecture(), architecture);
            assert_eq!(decoder.syntax(), Syntax::Att);
            assert!(!decoder.real_mode());
            assert!(Decoder::with_architecture(architecture, Syntax::Intel, true).is_err());
        }
    }

    /*
    This test checks independent ARM64 NOP, MOV, and RET vectors.
    Invalid input uses four-byte data units, while a short tail uses its remaining bytes.
    */
    #[test]
    fn arm64_instructions_and_truncated_data() {
        let decoder =
            Decoder::with_architecture(Architecture::Arm64, Syntax::Intel, false).unwrap();
        for (bytes, expected) in [
            (&[0x1f, 0x20, 0x03, 0xd5][..], "nop"),
            (&[0x00, 0x00, 0x80, 0xd2][..], "mov          x0, #0"),
            (&[0xc0, 0x03, 0x5f, 0xd6][..], "ret"),
        ] {
            let instruction = decoder.decode(bytes, 0, 0x1000).unwrap();
            assert_eq!(instruction.size, 4);
            assert_eq!(instruction.text, expected);
        }
        assert_eq!(
            decoder.decode(&[0x1f, 0x20, 0x03], 0, 0x1000).unwrap_err(),
            "Invalid or incomplete ARM64 instruction at offset 0."
        );
        let bytes = [0xff, 0xff, 0xff, 0xff, 0x1f, 0x20, 0x03, 0xd5];
        let fallback = decoder.decode_or_byte(&bytes, 0, 0x1000).unwrap();
        assert_eq!(
            (fallback.size, fallback.hex.as_str(), fallback.text.as_str()),
            (4, "FFFFFFFF", "db           0xFF, 0xFF, 0xFF, 0xFF")
        );
        assert_eq!(decoder.decode(&bytes, 4, 0x1004).unwrap().text, "nop");
        let tail = decoder.decode_or_byte(&[0x90], 0, 0x1004).unwrap();
        assert_eq!(
            (tail.size, tail.hex.as_str(), tail.text.as_str()),
            (1, "90", "db           0x90")
        );
    }

    /*
    This test checks independent ARMv6, Thumb-16, and Thumb-32 vectors.
    Invalid units preserve the natural architecture size and allow the next valid decode.
    */
    #[test]
    fn arm_and_thumb_instructions_use_fixed_decode_units() {
        let arm = Decoder::with_architecture(Architecture::Arm, Syntax::Intel, false).unwrap();
        for (bytes, expected) in [
            (&[0x00, 0x00, 0xa0, 0xe1][..], "mov          r0, r0"),
            (&[0x01, 0x00, 0xa0, 0xe3][..], "mov          r0, #1"),
            (&[0x00, 0x00, 0x00, 0xea][..], "b            #0x1008"),
            (&[0x02, 0x00, 0x00, 0xeb][..], "bl           #0x1010"),
        ] {
            let instruction = arm.decode(bytes, 0, 0x1000).unwrap();
            assert_eq!(instruction.size, 4);
            assert_eq!(instruction.text, expected);
        }
        let arm_bytes = [0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0xa0, 0xe1];
        let fallback = arm.decode_or_byte(&arm_bytes, 0, 0x1000).unwrap();
        assert_eq!((fallback.size, fallback.hex.as_str()), (4, "FFFFFFFF"));
        assert_eq!(
            arm.decode(&arm_bytes, 4, 0x1004).unwrap().text,
            "mov          r0, r0"
        );
        assert_eq!(
            arm.decode_or_byte(&[0x00, 0x00, 0xa0], 0, 0x1000)
                .unwrap()
                .size,
            3
        );

        let thumb = Decoder::with_architecture(Architecture::Thumb, Syntax::Intel, false).unwrap();
        for (bytes, size, expected) in [
            (&[0x01, 0x20][..], 2, "movs         r0, #1"),
            (&[0x00, 0xbf][..], 2, "nop"),
            (&[0xfe, 0xe7][..], 2, "b            #0x1000"),
            (&[0x00, 0xf0, 0x00, 0xf8][..], 4, "bl           #0x1004"),
        ] {
            let instruction = thumb.decode(bytes, 0, 0x1000).unwrap();
            assert_eq!(instruction.size, size);
            assert_eq!(instruction.text, expected);
        }
        let thumb_bytes = [0xff, 0xff, 0x01, 0x20];
        let fallback = thumb.decode_or_byte(&thumb_bytes, 0, 0x1000).unwrap();
        assert_eq!((fallback.size, fallback.hex.as_str()), (2, "FFFF"));
        assert_eq!(
            thumb.decode(&thumb_bytes, 2, 0x1002).unwrap().text,
            "movs         r0, #1"
        );
        assert_eq!(thumb.decode_or_byte(&[0x00], 0, 0x1000).unwrap().size, 1);
    }

    /*
    This test documents that native ARM inspection accepts unaligned runtime addresses.
    Range checks still reject a bounded instruction whose final runtime byte overflows u64.
    */
    #[test]
    fn arm_family_addresses_accept_unaligned_values_and_reject_overflow() {
        for (architecture, bytes, exact_end, expected) in [
            (
                Architecture::Arm,
                &[0x00, 0x00, 0xa0, 0xe1][..],
                u64::MAX - 3,
                "mov          r0, r0",
            ),
            (
                Architecture::Thumb,
                &[0x01, 0x20][..],
                u64::MAX - 1,
                "movs         r0, #1",
            ),
            (
                Architecture::Arm64,
                &[0x1f, 0x20, 0x03, 0xd5][..],
                u64::MAX - 3,
                "nop",
            ),
        ] {
            let decoder = Decoder::with_architecture(architecture, Syntax::Intel, false).unwrap();
            let aligned = decoder.decode(bytes, 0, 0x1000).unwrap();
            let unaligned = decoder.decode(bytes, 0, 0x1001).unwrap();
            assert_eq!(
                (unaligned.size, unaligned.text),
                (aligned.size, aligned.text)
            );
            let boundary = decoder.decode(bytes, 0, exact_end).unwrap();
            assert_eq!(
                (boundary.size, boundary.text.as_str()),
                (bytes.len(), expected)
            );
            assert_eq!(decoder.direct_target(bytes, exact_end), Ok(None));
            for error in [
                decoder.decode(bytes, 0, u64::MAX).unwrap_err(),
                decoder.decode_or_byte(bytes, 0, u64::MAX).unwrap_err(),
                decoder.direct_target(bytes, u64::MAX).unwrap_err(),
            ] {
                assert_eq!(
                    error,
                    "The ARM instruction exceeds the runtime address range."
                );
            }
            assert!(decoder.decode(&[], 0, 0x1000).is_err());
            assert!(decoder.direct_target(&[], 0x1000).is_err());
            assert_eq!(decoder.decode(bytes, 0, 0x1000).unwrap().size, bytes.len());
        }
    }

    /*
    This test checks ARM64 B, CBZ, and TBZ targets through the final immediate operand.
    An indirect RET remains targetless, and later decoding proves reusable detail state.
    */
    #[test]
    fn arm64_direct_relative_targets_use_the_final_immediate_operand() {
        let decoder =
            Decoder::with_architecture(Architecture::Arm64, Syntax::Intel, false).unwrap();
        assert_eq!(
            decoder.direct_target(&[0, 0, 0, 0x14], 0x1000),
            Ok(Some(0x1000))
        );
        assert_eq!(
            decoder.direct_target(&[0x20, 0, 0, 0xb4], 0x1000),
            Ok(Some(0x1004))
        );
        assert_eq!(
            decoder.direct_target(&[0x20, 0, 0, 0x36], 0x1000),
            Ok(Some(0x1004))
        );
        assert_eq!(
            decoder.direct_target(&[0xc0, 0x03, 0x5f, 0xd6], 0x1000),
            Ok(None)
        );
        assert_eq!(
            decoder
                .decode(&[0x1f, 0x20, 0x03, 0xd5], 0, 0x1000)
                .unwrap()
                .text,
            "nop"
        );
    }

    /*
    This test checks ARM and Thumb B or BL targets through the native relative-branch group.
    BLX and indirect transfers remain targetless because this helper cannot change execution state.
    */
    #[test]
    fn arm_and_thumb_direct_targets_preserve_execution_state() {
        let arm = Decoder::with_architecture(Architecture::Arm, Syntax::Intel, false).unwrap();
        assert_eq!(
            arm.direct_target(&[0x00, 0x00, 0x00, 0xea], 0x1000),
            Ok(Some(0x1008))
        );
        assert_eq!(
            arm.direct_target(&[0x02, 0x00, 0x00, 0xeb], 0x1000),
            Ok(Some(0x1010))
        );
        assert_eq!(
            arm.direct_target(&[0x02, 0x00, 0x00, 0xfa], 0x1000),
            Ok(None)
        );
        assert_eq!(
            arm.direct_target(&[0x10, 0xff, 0x2f, 0xe1], 0x1000),
            Ok(None)
        );
        assert_eq!(
            arm.decode(&[0x00, 0x00, 0xa0, 0xe1], 0, 0x1000)
                .unwrap()
                .size,
            4
        );

        let thumb = Decoder::with_architecture(Architecture::Thumb, Syntax::Intel, false).unwrap();
        assert_eq!(thumb.direct_target(&[0xfe, 0xe7], 0x1000), Ok(Some(0x1000)));
        assert_eq!(
            thumb.direct_target(&[0x00, 0xf0, 0x06, 0xf8], 0x1000),
            Ok(Some(0x1010))
        );
        assert_eq!(
            thumb.direct_target(&[0x00, 0xf0, 0x06, 0xe8], 0x1000),
            Ok(None)
        );
        assert_eq!(thumb.direct_target(&[0x00, 0x47], 0x1000), Ok(None));
        assert_eq!(thumb.decode(&[0x01, 0x20], 0, 0x1000).unwrap().size, 2);
    }

    /*
    This test compares Real16 acceptance with the pinned Zydis policy.
    It checks protected instructions, vector prefixes, far pointers, and accepted legacy forms.
    */
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
            for bytes in [
                &[0x0f, 0x79, 0x00][..],
                &[0x67, 0x0f, 0x79, 0x00],
                &[0x0f, 0x79, 0x46, 0xc0],
                &[0x0f, 0x79, 0x86, 0xc0, 0xc0],
                &[0x67, 0x0f, 0x79, 0x44, 0x24, 0xc0],
            ] {
                assert!(decoder.decode(bytes, 0, 0).is_err());
            }
        }
        let fallback = real.decode_or_byte(&[0x0f, 0x34], 0, 0).unwrap();
        assert_eq!((fallback.size, fallback.text.as_str()), (1, "db 0F"));
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

    /*
    This test checks 16-bit wrapping only for relative control-flow targets.
    Far pointers and syntax variants retain their established text.
    */
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

    /*
    This test obtains direct targets through Capstone branch groups in both syntax modes.
    It checks address wrapping at each supported x86 width.
    */
    #[test]
    fn direct_relative_targets_use_branch_groups_and_selected_syntax() {
        for syntax in [Syntax::Intel, Syntax::Att] {
            let decoder16 = Decoder::with_syntax(16, syntax).unwrap();
            let decoder32 = Decoder::with_syntax(32, syntax).unwrap();
            let decoder64 = Decoder::with_syntax(64, syntax).unwrap();
            assert_eq!(
                decoder32.direct_target(&[0xe8, 0, 0, 0, 0], 0x1000),
                Ok(Some(0x1005))
            );
            assert_eq!(
                decoder32.direct_target(&[0xeb, 2], 0x1000),
                Ok(Some(0x1004))
            );
            assert_eq!(
                decoder32.direct_target(&[0x75, 0xfc], 0x1000),
                Ok(Some(0x0ffe))
            );
            assert_eq!(
                decoder32.direct_target(&[0xe2, 0xfe], 0x1000),
                Ok(Some(0x1000))
            );
            assert_eq!(
                decoder16.direct_target(&[0x67, 0xe3, 0], 0x1000),
                Ok(Some(0x1003))
            );
            assert_eq!(decoder32.direct_target(&[0xeb, 0], 0), Ok(Some(2)));
            assert_eq!(
                decoder16.direct_target(&[0xeb, 0], 0xfffe),
                Ok(Some(0x10000))
            );
            assert_eq!(
                decoder32.direct_target(&[0xeb, 0], u32::MAX as u64 - 1),
                Ok(Some(0))
            );
            assert_eq!(
                decoder64.direct_target(&[0xeb, 0], u64::MAX - 1),
                Ok(Some(0))
            );
            assert_eq!(decoder32.syntax(), syntax);
        }
    }

    /*
    This test applies Real16 policy to direct-target decoding and restores detail mode.
    Indirect, invalid, and ordinary instructions keep their distinct results.
    */
    #[test]
    fn direct_target_applies_real16_policy_and_restores_detail() {
        for syntax in [Syntax::Intel, Syntax::Att] {
            let linear = Decoder::with_syntax(16, syntax).unwrap();
            let real = Decoder::with_mode(16, syntax, true).unwrap();
            assert_eq!(linear.direct_target(&[0xeb, 0], 0xfffe), Ok(Some(0x10000)));
            assert_eq!(real.direct_target(&[0xeb, 0], 0xfffe), Ok(Some(0)));
            assert_eq!(
                linear.direct_target(&[0xeb, 0xfe], 0x10000),
                Ok(Some(0x10000))
            );
            assert_eq!(real.direct_target(&[0xeb, 0xfe], 0x10000), Ok(Some(0)));
            assert!(real.direct_target(&[0x0f, 0x34], 0).is_err());
            assert_eq!(real.direct_target(&[0xff, 0xd0], 0), Ok(None));
            assert_eq!(real.direct_target(&[0xff, 0xe0], 0), Ok(None));
            assert_eq!(
                real.direct_target(&[0x9a, 0x78, 0x56, 0x34, 0x12], 0),
                Ok(None)
            );
            assert_eq!(real.direct_target(&[0x90], 0), Ok(None));
            assert!(real.direct_target(&[0x0f], 0).is_err());
            assert!(real.direct_target(&[], 0).is_err());
            assert_eq!(real.decode(&[0x90], 0, 0).unwrap().text, "nop");
            assert_eq!(real.syntax(), syntax);
        }
    }
}
