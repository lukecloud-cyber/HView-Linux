/*
This module maps file offsets and runtime addresses for supported executable formats.
The shared architecture contract gives decoder and assembler callers one validated source of machine facts.
*/
const OUTSIDE: &str = "Offset is out of file";

/*
Architecture identifies the instruction family and the effective code width.
Each engine validates a directly constructed x86 value before it uses the width.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    X86(u32),
    Arm,
    Thumb,
    Arm64,
}

impl Architecture {
    /*
    This constructor accepts only widths that the x86 engines support.
    Callers can use the remaining methods for bounded instruction and alignment decisions.
    */
    pub fn x86(bits: u32) -> Result<Self, String> {
        matches!(bits, 16 | 32 | 64)
            .then_some(Self::X86(bits))
            .ok_or_else(|| "The x86 code width must be 16, 32, or 64 bits.".into())
    }

    /*
    This fact returns the compatibility width used by existing Code display and session data.
    X86 stores its checked width, ARM and Thumb use 32, and ARM64 uses 64.
    */
    pub const fn bits(self) -> u32 {
        match self {
            Self::X86(bits) => bits,
            Self::Arm | Self::Thumb => 32,
            Self::Arm64 => 64,
        }
    }

    /*
    This fact gives the natural instruction alignment for each architecture family.
    X86 permits each byte, ARM and ARM64 use four bytes, and Thumb uses two bytes.
    Native inspection entry points can accept unaligned runtime addresses.
    */
    pub const fn alignment(self) -> u64 {
        match self {
            Self::X86(_) => 1,
            Self::Arm | Self::Arm64 => 4,
            Self::Thumb => 2,
        }
    }

    /*
    This fact bounds one native decoder input without selecting an engine.
    X86 permits 15 bytes, while the recorded ARM families need at most four bytes.
    */
    pub const fn max_instruction_bytes(self) -> usize {
        match self {
            Self::X86(_) => 15,
            Self::Arm | Self::Thumb | Self::Arm64 => 4,
        }
    }

    /*
    This fact validates a returned instruction length for the checked architecture family.
    X86 uses 1 through 15 bytes, ARM and ARM64 use four, and Thumb uses two or four.
    */
    pub const fn valid_instruction_bytes(self, size: usize) -> bool {
        match self {
            Self::X86(_) => size >= 1 && size <= 15,
            Self::Arm | Self::Arm64 => size == 4,
            Self::Thumb => size == 2 || size == 4,
        }
    }
}

/*
AddressDomain states how a CodeLocation address relates to the source bytes.
Raw models and mapped PE bytes use virtual addresses, while plain sources use file offsets.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressDomain {
    File,
    Va,
}

/*
CodeLocation joins one mapped address with its compatibility width, checked architecture, and address domain.
Callers can retain all four fields or use the older tuple wrapper.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeLocation {
    pub address: u64,
    pub bits: u32,
    pub architecture: Architecture,
    pub domain: AddressDomain,
}

/*
These readers decode fixed-width PE fields after they validate the requested source range.
Malformed input produces the existing executable-header error.
*/

fn word(data: &[u8], at: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        data.get(at..at + 2)
            .ok_or("The executable header is incomplete.")?
            .try_into()
            .unwrap(),
    ))
}

fn dword(data: &[u8], at: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        data.get(at..at + 4)
            .ok_or("The executable header is incomplete.")?
            .try_into()
            .unwrap(),
    ))
}

/*
Section stores one PE section mapping between file bytes and virtual extent.
Pe combines validated header fields and sections for later address conversion.
*/
struct Section {
    rva: u32,
    raw: u32,
    available: u32,
    extent: u32,
}

struct Pe {
    entry: u32,
    machine: u16,
    bits: u32,
    image_base: u64,
    header_size: u32,
    upper_rva: u32,
    direct: bool,
    first_file_offset: u32,
    sections: Vec<Section>,
}

/*
Raw stores the explicit runtime base and validated x86 architecture.
Checked conversions protect both the 64-bit range and the selected linear-address range.
*/
#[derive(Clone, Copy)]
struct Raw {
    base: u64,
    architecture: Architecture,
}

impl Raw {
    /*
    This conversion adds a file offset to the configured runtime base.
    The selected x86 width limits the resulting linear address.
    */
    fn address(self, offset: u64) -> Result<u64, String> {
        let address = self
            .base
            .checked_add(offset)
            .ok_or("The raw address exceeds the 64-bit address range.")?;
        if self.architecture.bits() != 64 && address > u64::from(u32::MAX) {
            return Err("The raw address exceeds the 32-bit linear address range.".into());
        }
        Ok(address)
    }

    /*
    This reverse conversion subtracts the runtime base after width validation.
    An address below the base has no raw file offset.
    */
    fn offset(self, address: u64) -> Result<u64, String> {
        if self.architecture.bits() != 64 && address > u64::from(u32::MAX) {
            return Err("The raw address exceeds the 32-bit linear address range.".into());
        }
        address
            .checked_sub(self.base)
            .ok_or_else(|| "The address is below the raw runtime base.".into())
    }
}

/*
Metadata selects either parsed PE mapping or an explicit raw x86 mapping.
Callers reuse the value for code addresses, navigation, and address conversion.
*/
pub struct Metadata {
    pe: Option<Pe>,
    raw: Option<Raw>,
}

/*
These methods construct metadata and expose checked mapping operations.
Each operation preserves the error that identifies an unsupported machine or missing byte.
*/
impl Metadata {
    /*
    This parser accepts current PE data and preserves the existing raw ELF fallback.
    A malformed executable header stops metadata construction.
    */
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.starts_with(b"\x7fELF") {
            return Ok(Self {
                pe: None,
                raw: None,
            });
        }
        let pe = pe_header(data)?
            .map(|header| Pe::read(data, header))
            .transpose()?;
        Ok(Self { pe, raw: None })
    }

    /*
    This constructor validates an explicit raw x86 base and width.
    It stores no parsed PE mapping.
    */
    pub fn raw(base: u64, bits: u32) -> Result<Self, String> {
        let architecture = Architecture::x86(bits)
            .map_err(|_| "Raw x86 code width must be 16, 32, or 64 bits.".to_owned())?;
        let raw = Raw { base, architecture };
        raw.address(0)?;
        Ok(Self {
            pe: None,
            raw: Some(raw),
        })
    }

    /*
    This query returns an address, architecture, and domain for one existing code mapping.
    It preserves PE mapping failures and unsupported machine errors.
    */
    pub fn code_location(&self, file_offset: u64) -> Result<CodeLocation, String> {
        if let Some(raw) = self.raw {
            return Ok(CodeLocation {
                address: raw.address(file_offset)?,
                bits: raw.architecture.bits(),
                architecture: raw.architecture,
                domain: AddressDomain::Va,
            });
        }
        self.validate_code_machine()?;
        match &self.pe {
            Some(pe) => pe
                .file_to_virtual(file_offset)
                .map(|address| CodeLocation {
                    address,
                    bits: pe.bits,
                    architecture: Architecture::X86(pe.bits),
                    domain: AddressDomain::Va,
                })
                .ok_or_else(|| OUTSIDE.into()),
            None => Ok(CodeLocation {
                address: file_offset,
                bits: 16,
                architecture: Architecture::X86(16),
                domain: AddressDomain::File,
            }),
        }
    }

    /*
    This compatibility wrapper preserves the existing address and width tuple.
    New callers can retain the address domain when their operation requires it.
    */
    pub fn code_address(&self, file_offset: u64) -> Result<(u64, u32), String> {
        let location = self.code_location(file_offset)?;
        Ok((location.address, location.bits))
    }

    /*
    This navigation query validates a source file byte before returning its runtime address.
    PE sources require a mapped virtual address.
    */
    pub fn navigation_address(&self, data: &[u8], file_offset: u64) -> Result<u64, String> {
        if let Some(raw) = self.raw {
            let offset = usize::try_from(file_offset)
                .map_err(|_| "The branch source exceeds the address range.")?;
            data.get(offset)
                .ok_or("The branch source is outside the current buffer.")?;
            return raw.address(file_offset);
        }
        self.validate_code_machine()?;
        if self.pe.is_some() || data.starts_with(b"MZ") || data.starts_with(b"ZM") {
            return convert_address(data, AddressKind::File, file_offset)?
                .va
                .ok_or_else(|| "The branch source has no virtual address.".into());
        }
        let offset = usize::try_from(file_offset)
            .map_err(|_| "The branch source exceeds the address range.")?;
        data.get(offset)
            .map(|_| file_offset)
            .ok_or_else(|| "The branch source is outside the current buffer.".into())
    }

    /*
    This navigation query maps a runtime address back to one source file byte.
    Raw, PE, and plain sources retain their established bounds.
    */
    pub fn navigation_offset(&self, data: &[u8], address: u64) -> Result<u64, String> {
        if let Some(raw) = self.raw {
            let offset = raw.offset(address)?;
            let index = usize::try_from(offset)
                .map_err(|_| "The branch target exceeds the address range.")?;
            data.get(index)
                .ok_or("The branch target is outside the current buffer.")?;
            return Ok(offset);
        }
        if self.pe.is_some() || data.starts_with(b"MZ") || data.starts_with(b"ZM") {
            let offset = convert_address(data, AddressKind::Va, address)?
                .file_offset
                .ok_or("The branch target has no file byte.")?;
            return u64::try_from(offset)
                .map_err(|_| "The branch target exceeds the address range.".into());
        }
        let offset =
            usize::try_from(address).map_err(|_| "The branch target exceeds the address range.")?;
        data.get(offset)
            .map(|_| address)
            .ok_or_else(|| "The branch target is outside the current buffer.".into())
    }

    /*
    This general conversion returns all available raw or PE address domains.
    Raw models reject RVA requests because they define no image-relative base.
    */
    pub fn convert_address(
        &self,
        data: &[u8],
        kind: AddressKind,
        value: u64,
    ) -> Result<PeAddress, String> {
        let Some(raw) = self.raw else {
            return convert_address(data, kind, value);
        };
        match kind {
            AddressKind::File => {
                let file_offset = usize::try_from(value)
                    .map_err(|_| "The file offset exceeds the address range.")?;
                data.get(file_offset)
                    .ok_or("The file offset has no file byte.")?;
                Ok(PeAddress {
                    file_offset: Some(file_offset),
                    rva: None,
                    va: Some(raw.address(value)?),
                })
            }
            AddressKind::Va => {
                let offset = raw.offset(value)?;
                let file_offset = usize::try_from(offset)
                    .map_err(|_| "The file offset exceeds the address range.")?;
                data.get(file_offset)
                    .ok_or("The converted file offset has no file byte.")?;
                Ok(PeAddress {
                    file_offset: Some(file_offset),
                    rva: None,
                    va: Some(value),
                })
            }
            AddressKind::Rva => Err("Raw address mode has no RVA.".into()),
        }
    }

    /*
    This validation accepts only the existing x86 PE machine identifiers.
    Later architecture goals own additional executable-machine support.
    */
    fn validate_code_machine(&self) -> Result<(), String> {
        if let Some(pe) = &self.pe
            && !matches!(pe.machine, 332 | 34404)
        {
            return Err("The PE processor is unsupported for code decoding.".into());
        }
        Ok(())
    }
}

/*
These PE methods retain the legacy parser and mapping arithmetic for existing code paths.
The parsed sections remain immutable after construction.
*/
impl Pe {
    /*
    This parser reads legacy PE headers and section records from the supplied bytes.
    It normalizes alignments and rejects incomplete tables or the specific header and first-section overlap.
    It does not reject all invalid alignments or ambiguous section ranges.
    */
    fn read(data: &[u8], header: usize) -> Result<Self, String> {
        /*
        The first section validates the COFF and optional headers.
        It derives image geometry before section-table reads begin.
        */
        let file_size =
            u32::try_from(data.len()).map_err(|_| "PE files above 4 GB are unsupported.")?;
        let count = usize::from(word(data, header + 6)?);
        let optional_size = usize::from(word(data, header + 20)?);
        let optional = header + 24;
        let magic = word(data, optional)?;
        let image_base = match magic {
            0x10b => u64::from(dword(data, optional + 28)?),
            0x20b => {
                u64::from(dword(data, optional + 24)?)
                    | (u64::from(dword(data, optional + 28)?) << 32)
            }
            _ => return Err("The PE optional-header type is unsupported.".into()),
        };
        if optional_size < 64 {
            return Err("The PE optional header is incomplete.".into());
        }
        let section_alignment = dword(data, optional + 32)?;
        let file_alignment = dword(data, optional + 36)?;
        let direct = count == 0 || section_alignment < 4096 && section_alignment == file_alignment;
        let section_alignment = if section_alignment == 0 {
            4096
        } else {
            section_alignment
        };
        let file_alignment = if file_alignment == 0 {
            512
        } else {
            file_alignment
        };
        let mut pe = Self {
            entry: dword(data, optional + 16)?,
            machine: word(data, header + 4)?,
            bits: if magic == 0x20b { 64 } else { 32 },
            image_base,
            header_size: dword(data, optional + 60)?,
            upper_rva: dword(data, optional + 56)?,
            direct,
            first_file_offset: if direct { 0 } else { header as u32 },
            sections: Vec::with_capacity(count),
        };
        let mut first_raw_pointer = u32::MAX;
        let table = optional + optional_size;
        if data.get(table..table + count * 40).is_none() {
            return Err("The PE section table is incomplete.".into());
        }
        /*
        The second section normalizes each section range to the loader alignment.
        Available source bytes limit the virtual extent used for code mapping.
        */
        for index in 0..count {
            let at = table + index * 40;
            let virtual_size = dword(data, at + 8)?;
            let rva = dword(data, at + 12)?;
            let raw_size = dword(data, at + 16)?;
            let raw_pointer = dword(data, at + 20)?;
            if index == 0 && table > rva as usize {
                return Err("PE headers that overlap section addresses are unsupported.".into());
            }
            let raw = if direct {
                raw_pointer
            } else {
                raw_pointer & file_alignment.wrapping_neg()
            };
            let mut available = 0;
            if raw_pointer != 0 && raw_size != 0 {
                available = if direct {
                    raw_size
                } else {
                    raw_size.wrapping_add(file_alignment).wrapping_sub(1)
                        & file_alignment.wrapping_neg()
                };
                if available.wrapping_add(raw) > file_size {
                    available = file_size.wrapping_sub(raw);
                }
            }
            let size = if virtual_size == 0 {
                raw_size
            } else {
                virtual_size
            };
            let mut extent = if size == 0 {
                0
            } else {
                section_alignment.wrapping_mul(
                    size.wrapping_add(section_alignment).wrapping_sub(1) / section_alignment,
                )
            };
            if available != 0 && extent > available {
                extent = available;
            }
            if available != 0 && raw_pointer < first_raw_pointer {
                first_raw_pointer = raw_pointer;
                pe.first_file_offset = (header as u32).min(raw);
            }
            pe.upper_rva = rva.wrapping_add(extent);
            pe.sections.push(Section {
                rva,
                raw,
                available,
                extent,
            });
        }
        Ok(pe)
    }

    /*
    This helper uses a direct mapping shortcut when the legacy layout permits one.
    Other layouts use the retained section and header mapping arithmetic.
    */
    fn rva_to_file(&self, rva: u32) -> Option<u32> {
        if self.direct {
            return Some(rva);
        }
        if rva != 0 && rva < self.upper_rva {
            for section in &self.sections {
                if section.available != 0
                    && rva >= section.rva
                    && rva < section.rva.wrapping_add(section.extent)
                {
                    return Some(rva.wrapping_sub(section.rva).wrapping_add(section.raw));
                }
            }
        }
        (rva < self.header_size).then_some(rva)
    }

    /*
    This helper first tries an image-relative candidate, and then it tries the supplied value as an RVA.
    Each candidate uses the retained legacy RVA mapper.
    */
    fn virtual_to_file(&self, address: u64) -> Option<u32> {
        let rva = if address != u64::MAX && address >= self.image_base {
            address - self.image_base
        } else {
            address
        };
        for candidate in [rva, address] {
            if candidate <= u64::from(self.upper_rva)
                && let Some(offset) = self
                    .rva_to_file(candidate as u32)
                    .filter(|v| *v != u32::MAX)
            {
                return Some(offset);
            }
        }
        None
    }

    /*
    This helper preserves the legacy direct, section, and header arithmetic for file-to-virtual mapping.
    The helper uses stored ranges and wrapping address operations.
    */
    fn file_to_virtual(&self, offset: u64) -> Option<u64> {
        if self.direct {
            return (offset < u64::from(self.upper_rva))
                .then(|| self.image_base.wrapping_add(offset));
        }
        let low = offset as u32;
        if offset >= u64::from(self.first_file_offset) {
            for section in &self.sections {
                if section.available != 0
                    && low >= section.raw
                    && low < section.raw.wrapping_add(section.available)
                    && low.wrapping_sub(section.raw) < section.extent
                {
                    let rva = low.wrapping_add(section.rva).wrapping_sub(section.raw);
                    return Some(self.image_base.wrapping_add(u64::from(rva)));
                }
            }
        }
        (offset < u64::from(self.header_size)).then(|| self.image_base.wrapping_add(u64::from(low)))
    }
}

/*
These constants name PE directories and bound browser table and string reads.
The table and string limits are separate from the caller's final row cap.
*/
const DIRECTORY_NAMES: [&str; 16] = [
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Security",
    "Relocation",
    "Debug",
    "Architecture",
    "Global pointer",
    "TLS",
    "Load configuration",
    "Bound import",
    "Import address table",
    "Delay import",
    "CLR runtime header",
    "Reserved",
];
const MAX_BROWSER_ENTRIES: usize = 100_000;
const MAX_NAME_BYTES: usize = 4_096;

/*
AddressKind identifies the user input domain for general address conversion.
PeAddress returns every domain that the selected source location can represent.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    File,
    Rva,
    Va,
}

/*
PeAddress contains each available file, RVA, and virtual-address result.
An absent field identifies a valid partial mapping.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeAddress {
    pub file_offset: Option<usize>,
    pub rva: Option<u32>,
    pub va: Option<u64>,
}

/*
These browser records retain validated PE directory and section data for structure rows.
The browser keeps display limits separate from file mapping validation.
*/
#[derive(Clone, Copy)]
struct BrowserDirectory {
    rva: u32,
    size: u32,
}

struct BrowserSection {
    name: String,
    header: usize,
    virtual_size: u32,
    rva: u32,
    raw_size: u32,
    raw: u32,
    characteristics: u32,
}

struct BrowserPe {
    bits: u32,
    image_base: u64,
    header_size: u32,
    sections: Vec<BrowserSection>,
    directories: [Option<BrowserDirectory>; 16],
}

/*
These fixed-width helpers validate PE browser ranges before they read little-endian values.
Later import and export readers use the same checked arithmetic.
*/
fn browser_range(data: &[u8], at: usize, size: usize, what: &str) -> Result<(), String> {
    at.checked_add(size)
        .filter(|&end| end <= data.len())
        .ok_or_else(|| format!("The {what} range is outside the file."))?;
    Ok(())
}

fn browser_word(data: &[u8], at: usize, what: &str) -> Result<u16, String> {
    browser_range(data, at, 2, what)?;
    Ok(u16::from_le_bytes(data[at..at + 2].try_into().unwrap()))
}

fn browser_dword(data: &[u8], at: usize, what: &str) -> Result<u32, String> {
    browser_range(data, at, 4, what)?;
    Ok(u32::from_le_bytes(data[at..at + 4].try_into().unwrap()))
}

fn browser_qword(data: &[u8], at: usize, what: &str) -> Result<u64, String> {
    browser_range(data, at, 8, what)?;
    Ok(u64::from_le_bytes(data[at..at + 8].try_into().unwrap()))
}

/*
This helper escapes control and non-ASCII bytes for browser row text.
The output does not change the source name or its file offset.
*/
fn escaped(bytes: &[u8]) -> String {
    let mut text = String::new();
    for &byte in bytes {
        for value in std::ascii::escape_default(byte) {
            text.push(char::from(value));
        }
    }
    text
}

/*
This helper checks one table count against the browser entry cap and byte-size arithmetic.
The returned byte count does not limit the final display row count.
*/
fn checked_count(count: u32, unit: usize, what: &str) -> Result<usize, String> {
    let count = usize::try_from(count).map_err(|_| format!("The {what} count is too large."))?;
    if count > MAX_BROWSER_ENTRIES {
        return Err(format!(
            "The {what} count exceeds the browser limit of {MAX_BROWSER_ENTRIES}."
        ));
    }
    count
        .checked_mul(unit)
        .ok_or_else(|| format!("The {what} range exceeds the address range."))
}

/*
BrowserPe validates its own PE browser map from current source bytes.
Its methods resolve source-backed ranges before they create user-visible structure rows.
*/
impl BrowserPe {
    /*
    This parser validates browser-specific PE fields and section records.
    The resulting map supports later directory, import, and export rows.
    */
    fn parse(data: &[u8]) -> Result<Self, String> {
        /*
        The first section validates the DOS, COFF, and optional headers.
        It obtains the address width and table bounds for later records.
        */
        if data.len() > u32::MAX as usize {
            return Err("PE files above 4 GB are unsupported.".into());
        }
        if !data.starts_with(b"MZ") && !data.starts_with(b"ZM") {
            return Err("The file is not a PE file.".into());
        }
        let header = browser_dword(data, 60, "DOS header")? as usize;
        browser_range(data, header, 24, "PE header")?;
        if &data[header..header + 4] != b"PE\0\0" {
            return Err("The file is not a PE file.".into());
        }
        let section_count = usize::from(browser_word(data, header + 6, "COFF header")?);
        if section_count > 96 {
            return Err("The PE section count exceeds the Windows limit of 96.".into());
        }
        let optional_size = usize::from(browser_word(data, header + 20, "COFF header")?);
        let optional = header
            .checked_add(24)
            .ok_or("The optional-header offset exceeds the address range.")?;
        browser_range(data, optional, optional_size, "optional header")?;
        let magic = browser_word(data, optional, "optional header")?;
        let (bits, image_base, directory_start, directory_count_at) = match magic {
            0x10b => (
                32,
                u64::from(browser_dword(data, optional + 28, "PE32 image base")?),
                96usize,
                92usize,
            ),
            0x20b => (
                64,
                browser_qword(data, optional + 24, "PE32+ image base")?,
                112usize,
                108usize,
            ),
            _ => return Err("The PE optional-header type is unsupported.".into()),
        };
        if optional_size < directory_start {
            return Err("The PE optional header is incomplete.".into());
        }
        let header_size = browser_dword(data, optional + 60, "header size")?;
        if header_size == 0 || header_size as usize > data.len() {
            return Err("The PE header range is outside the file.".into());
        }
        let directory_count =
            browser_dword(data, optional + directory_count_at, "data-directory count")? as usize;
        let directory_bytes = directory_count
            .checked_mul(8)
            .ok_or("The data-directory range exceeds the address range.")?;
        if directory_start
            .checked_add(directory_bytes)
            .is_none_or(|end| end > optional_size)
        {
            return Err("The data-directory table exceeds the optional header.".into());
        }
        let table = optional
            .checked_add(optional_size)
            .ok_or("The section-table offset exceeds the address range.")?;
        let table_size = section_count
            .checked_mul(40)
            .ok_or("The section-table range exceeds the address range.")?;
        browser_range(data, table, table_size, "section table")?;
        if table + table_size > header_size as usize {
            return Err("The section table exceeds the declared PE headers.".into());
        }

        /*
        The directory section records complete nonzero directory ranges.
        A half-empty directory entry cannot continue to section parsing.
        */
        let mut directories = [None; 16];
        for (index, slot) in directories
            .iter_mut()
            .enumerate()
            .take(directory_count.min(16))
        {
            let at = optional + directory_start + index * 8;
            let rva = browser_dword(data, at, "data-directory entry")?;
            let size = browser_dword(data, at + 4, "data-directory entry")?;
            if rva == 0 && size == 0 {
                continue;
            }
            if rva == 0 || size == 0 {
                return Err(format!(
                    "The {} directory has an incomplete range.",
                    DIRECTORY_NAMES[index]
                ));
            }
            *slot = Some(BrowserDirectory { rva, size });
        }

        /*
        The section-table section validates names, raw bytes, and virtual spans.
        The next overlap check receives only complete section records.
        */
        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let at = table + index * 40;
            let raw_name = &data[at..at + 8];
            let name_end = raw_name
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(raw_name.len());
            let name = escaped(&raw_name[..name_end]);
            let virtual_size = browser_dword(data, at + 8, "section header")?;
            let rva = browser_dword(data, at + 12, "section header")?;
            let raw_size = browser_dword(data, at + 16, "section header")?;
            let raw = browser_dword(data, at + 20, "section header")?;
            let characteristics = browser_dword(data, at + 36, "section header")?;
            let virtual_span = u64::from(virtual_size.max(raw_size));
            let virtual_end = u64::from(rva)
                .checked_add(virtual_span)
                .ok_or("A section virtual range exceeds the address range.")?;
            if virtual_end > u64::from(u32::MAX) + 1 {
                return Err("A section virtual range exceeds the PE address range.".into());
            }
            if virtual_span != 0 && rva < header_size {
                return Err("A section virtual range overlaps the PE headers.".into());
            }
            if raw_size != 0 {
                if raw == 0 {
                    return Err("A section with raw bytes has a zero file offset.".into());
                }
                if raw < header_size {
                    return Err("A section raw range overlaps the PE headers.".into());
                }
                browser_range(data, raw as usize, raw_size as usize, "section raw data")?;
            }
            sections.push(BrowserSection {
                name,
                header: at,
                virtual_size,
                rva,
                raw_size,
                raw,
                characteristics,
            });
        }

        /*
        The overlap section rejects ambiguous raw or virtual mappings.
        The final directory check then uses one unambiguous BrowserPe map.
        */
        for (index, left) in sections.iter().enumerate() {
            for right in &sections[index + 1..] {
                if ranges_overlap(left.raw, left.raw_size, right.raw, right.raw_size) {
                    return Err("Two section raw ranges overlap.".into());
                }
                if ranges_overlap(
                    left.rva,
                    left.virtual_size.max(left.raw_size),
                    right.rva,
                    right.virtual_size.max(right.raw_size),
                ) {
                    return Err("Two section virtual ranges overlap.".into());
                }
            }
        }

        /*
        The final section validates every directory against the completed map.
        Security uses a file offset, while other directories use RVAs.
        */
        let pe = Self {
            bits,
            image_base,
            header_size,
            sections,
            directories,
        };
        for (index, directory) in pe.directories.iter().enumerate() {
            let Some(directory) = directory else {
                continue;
            };
            if index == 4 {
                browser_range(
                    data,
                    directory.rva as usize,
                    directory.size as usize,
                    "Security directory",
                )?;
            } else {
                pe.map_range(data, directory.rva, directory.size, DIRECTORY_NAMES[index])?;
            }
        }
        Ok(pe)
    }

    /*
    This helper adds one RVA to the current image base with PE width checks.
    The supplied name identifies the failed structure when overflow occurs.
    */
    fn va(&self, rva: u32, what: &str) -> Result<u64, String> {
        let va = self
            .image_base
            .checked_add(u64::from(rva))
            .ok_or_else(|| format!("The {what} virtual address exceeds the address range."))?;
        if self.bits == 32 && va > u64::from(u32::MAX) {
            return Err(format!(
                "The {what} virtual address exceeds the PE32 address range."
            ));
        }
        Ok(va)
    }

    /*
    This helper resolves a complete RVA range to file bytes.
    Partial, virtual-only, and out-of-file ranges return an error.
    */
    fn map_range(&self, data: &[u8], rva: u32, size: u32, what: &str) -> Result<usize, String> {
        if size == 0 {
            return Err(format!("The {what} range is empty."));
        }
        let end = u64::from(rva)
            .checked_add(u64::from(size))
            .ok_or_else(|| format!("The {what} RVA range exceeds the address range."))?;
        let mut mapped = None;
        if rva < self.header_size && end <= u64::from(self.header_size) {
            mapped = Some(rva as usize);
        }
        for section in &self.sections {
            if rva < section.rva {
                continue;
            }
            let delta = u64::from(rva - section.rva);
            if delta < u64::from(section.virtual_size.max(section.raw_size))
                && delta + u64::from(size) <= u64::from(section.raw_size)
            {
                let file = u64::from(section.raw)
                    .checked_add(delta)
                    .ok_or_else(|| format!("The {what} file range exceeds the address range."))?;
                let file = usize::try_from(file)
                    .map_err(|_| format!("The {what} file range exceeds the address range."))?;
                if mapped.replace(file).is_some() {
                    return Err(format!("The {what} RVA range has ambiguous file mappings."));
                }
            }
        }
        let file = mapped.ok_or_else(|| format!("The {what} RVA range has no raw bytes."))?;
        browser_range(data, file, size as usize, what)?;
        Ok(file)
    }

    /*
    This helper returns a file byte when an RVA has current source data.
    A valid virtual-only address returns no file byte.
    */
    fn virtual_file(&self, data: &[u8], rva: u32, what: &str) -> Result<Option<usize>, String> {
        let mut result = None;
        if rva < self.header_size {
            browser_range(data, rva as usize, 1, what)?;
            result = Some(Some(rva as usize));
        }
        for section in &self.sections {
            if rva < section.rva {
                continue;
            }
            let delta = u64::from(rva - section.rva);
            if delta >= u64::from(section.virtual_size.max(section.raw_size)) {
                continue;
            }
            let file =
                if delta < u64::from(section.raw_size) {
                    let file = u64::from(section.raw) + delta;
                    Some(usize::try_from(file).map_err(|_| {
                        format!("The {what} file offset exceeds the address range.")
                    })?)
                } else {
                    None
                };
            if result.replace(file).is_some() {
                return Err(format!("The {what} RVA has ambiguous section mappings."));
            }
        }
        result.ok_or_else(|| format!("The {what} RVA is outside the PE image."))
    }

    /*
    This helper returns an RVA when a current file byte belongs to the PE image.
    Overlays and valid gaps return no RVA.
    */
    fn file_rva(&self, data: &[u8], file: usize, what: &str) -> Result<Option<u32>, String> {
        browser_range(data, file, 1, what)?;
        let mut result = (file < self.header_size as usize).then_some(file as u32);
        for section in &self.sections {
            let Some(delta) = file.checked_sub(section.raw as usize) else {
                continue;
            };
            if delta >= section.raw_size as usize {
                continue;
            }
            let rva = u64::from(section.rva)
                .checked_add(delta as u64)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| format!("The {what} RVA exceeds the PE address range."))?;
            if result.replace(rva).is_some() {
                return Err(format!(
                    "The {what} file offset has ambiguous RVA mappings."
                ));
            }
        }
        Ok(result)
    }

    /*
    This helper reads one bounded NUL-terminated string through an RVA mapping.
    Escaping produces safe structure-row text without changing source bytes.
    */
    fn string_at_rva(
        &self,
        data: &[u8],
        rva: u32,
        rva_limit: Option<u64>,
        what: &str,
    ) -> Result<(usize, String), String> {
        let file = self.map_range(data, rva, 1, what)?;
        let mut available = if rva < self.header_size {
            usize::try_from(self.header_size - rva).unwrap()
        } else {
            let section = self
                .sections
                .iter()
                .find(|section| {
                    rva >= section.rva && u64::from(rva - section.rva) < u64::from(section.raw_size)
                })
                .ok_or_else(|| format!("The {what} has no raw bytes."))?;
            usize::try_from(u64::from(section.raw_size) - u64::from(rva - section.rva)).unwrap()
        };
        if let Some(limit) = rva_limit {
            if u64::from(rva) >= limit {
                return Err(format!("The {what} starts outside its directory."));
            }
            available =
                available.min(usize::try_from(limit - u64::from(rva)).unwrap_or(usize::MAX));
        }
        available = available.min(data.len() - file);
        let scan = available.min(MAX_NAME_BYTES + 1);
        let Some(length) = data[file..file + scan].iter().position(|&byte| byte == 0) else {
            if available > MAX_NAME_BYTES {
                return Err(format!(
                    "The {what} exceeds the browser name limit of {MAX_NAME_BYTES} bytes."
                ));
            }
            return Err(format!("The {what} is not null-terminated."));
        };
        Ok((file, escaped(&data[file..file + length])))
    }
}

/*
This helper reports whether two nonempty 32-bit source ranges overlap.
PE parsing uses the result to reject ambiguous section mappings.
*/
fn ranges_overlap(left: u32, left_size: u32, right: u32, right_size: u32) -> bool {
    if left_size == 0 || right_size == 0 {
        return false;
    }
    let left = u64::from(left)..u64::from(left) + u64::from(left_size);
    let right = u64::from(right)..u64::from(right) + u64::from(right_size);
    left.start < right.end && right.start < left.end
}

/*
This helper alone applies the caller-supplied display row cap.
It preserves each accepted source offset and text pair.
*/
fn add_row(rows: &mut Vec<(usize, String)>, limit: usize, offset: usize, text: String) {
    if rows.len() < limit {
        rows.push((offset, text));
    }
}

/*
This helper calculates one indexed table RVA with checked multiplication and addition.
It also rejects values outside the PE 32-bit RVA range.
*/
fn indexed_rva(base: u32, index: usize, width: usize, what: &str) -> Result<u32, String> {
    let delta = index
        .checked_mul(width)
        .ok_or_else(|| format!("The {what} index exceeds the address range."))?;
    let value = u64::from(base)
        .checked_add(delta as u64)
        .ok_or_else(|| format!("The {what} RVA exceeds the address range."))?;
    u32::try_from(value).map_err(|_| format!("The {what} RVA exceeds the PE address range."))
}

/*
This reader walks validated import descriptors and their name or ordinal entries.
Each result carries the file offset that the structure browser can select.
*/
fn import_rows(
    pe: &BrowserPe,
    data: &[u8],
    rows: &mut Vec<(usize, String)>,
    limit: usize,
) -> Result<(), String> {
    /*
    The first section validates the import directory and selects the thunk width.
    Empty directories return without changing the row list.
    */
    let Some(directory) = pe.directories[1] else {
        return Ok(());
    };
    if directory.size as usize / 20 > MAX_BROWSER_ENTRIES + 1 {
        return Err(format!(
            "The import descriptor count exceeds the browser limit of {MAX_BROWSER_ENTRIES}."
        ));
    }
    let directory_file = pe.map_range(data, directory.rva, directory.size, "Import directory")?;
    let directory_end = directory_file + directory.size as usize;
    let thunk_width = if pe.bits == 64 { 8 } else { 4 };
    let ordinal_flag = if pe.bits == 64 {
        1u64 << 63
    } else {
        1u64 << 31
    };
    let mut descriptor_file = directory_file;
    let mut descriptor_index = 0usize;
    let mut thunk_count = 0usize;
    let mut terminated = false;
    /*
    The descriptor loop validates each DLL name and lookup-table source.
    It adds the descriptor row before its individual thunk rows.
    */
    while descriptor_file < directory_end {
        if descriptor_file + 20 > directory_end {
            return Err("The import descriptor table ends with a partial descriptor.".into());
        }
        let fields = [
            browser_dword(data, descriptor_file, "import descriptor")?,
            browser_dword(data, descriptor_file + 4, "import descriptor")?,
            browser_dword(data, descriptor_file + 8, "import descriptor")?,
            browser_dword(data, descriptor_file + 12, "import descriptor")?,
            browser_dword(data, descriptor_file + 16, "import descriptor")?,
        ];
        if fields.iter().all(|&value| value == 0) {
            terminated = true;
            break;
        }
        let lookup_rva = fields[0];
        let name_rva = fields[3];
        let iat_rva = fields[4];
        if name_rva == 0 || iat_rva == 0 {
            return Err("An import descriptor lacks its DLL name or import address table.".into());
        }
        let (_, dll) = pe.string_at_rva(data, name_rva, None, "import DLL name")?;
        let descriptor_rva = indexed_rva(directory.rva, descriptor_index, 20, "import descriptor")?;
        let descriptor_va = pe.va(descriptor_rva, "import descriptor")?;
        add_row(
            rows,
            limit,
            descriptor_file,
            format!(
                "Import {dll} | File={descriptor_file:08X} RVA={descriptor_rva:08X} VA={descriptor_va:016X} Size=00000014 | descriptor"
            ),
        );

        let fallback = lookup_rva == 0;
        let lookup_rva = if fallback { iat_rva } else { lookup_rva };
        let mut thunk_terminated = false;
        /*
        The thunk loop resolves each ordinal or name through checked file ranges.
        A zero entry terminates the current DLL table.
        */
        for index in 0..=MAX_BROWSER_ENTRIES {
            let lookup_entry_rva =
                indexed_rva(lookup_rva, index, thunk_width, "import lookup entry")?;
            let lookup_file = pe
                .map_range(
                    data,
                    lookup_entry_rva,
                    thunk_width as u32,
                    "import lookup entry",
                )
                .map_err(|_| {
                    "The import lookup table is not terminated within raw bytes.".to_string()
                })?;
            let value = if pe.bits == 64 {
                browser_qword(data, lookup_file, "import lookup entry")?
            } else {
                u64::from(browser_dword(data, lookup_file, "import lookup entry")?)
            };
            if value == 0 {
                thunk_terminated = true;
                break;
            }
            thunk_count += 1;
            if thunk_count > MAX_BROWSER_ENTRIES {
                return Err(format!(
                    "The import thunk count exceeds the browser limit of {MAX_BROWSER_ENTRIES}."
                ));
            }
            let iat_entry_rva = indexed_rva(iat_rva, index, thunk_width, "import address entry")?;
            let iat_file = pe.map_range(
                data,
                iat_entry_rva,
                thunk_width as u32,
                "import address entry",
            )?;
            let iat_va = pe.va(iat_entry_rva, "import address entry")?;
            let source = if fallback { " Source=IAT-fallback" } else { "" };
            let symbol = if value & ordinal_flag != 0 {
                if value & !(ordinal_flag | 0xffff) != 0 {
                    return Err("An ordinal import has nonzero reserved bits.".into());
                }
                format!("#{}", value & 0xffff)
            } else {
                let name_record_rva = match u32::try_from(value) {
                    Ok(value) => value,
                    Err(_) if fallback => {
                        return Err(
                            "The import address table contains a bound value without an import lookup table."
                                .into(),
                        );
                    }
                    Err(_) => return Err("An import name RVA exceeds the PE address range.".into()),
                };
                let name_rva = name_record_rva
                    .checked_add(2)
                    .ok_or("An import name RVA exceeds the PE address range.")?;
                let name_record_file = match pe.map_range(data, name_record_rva, 2, "import hint") {
                    Ok(file) => file,
                    Err(_) if fallback => {
                        return Err(
                            "The import address table contains a bound value without an import lookup table."
                                .into(),
                        );
                    }
                    Err(error) => return Err(error),
                };
                let hint = browser_word(data, name_record_file, "import hint")?;
                let (_, name) = match pe.string_at_rva(data, name_rva, None, "import name") {
                    Ok(name) => name,
                    Err(_) if fallback => {
                        return Err(
                            "The import address table contains a bound value without an import lookup table."
                                .into(),
                        );
                    }
                    Err(error) => return Err(error),
                };
                format!("{name} Hint={hint:04X}")
            };
            add_row(
                rows,
                limit,
                iat_file,
                format!(
                    "Import {dll}!{symbol} | File={iat_file:08X} RVA={iat_entry_rva:08X} VA={iat_va:016X} Size={thunk_width:08X} LookupFile={lookup_file:08X}{source}"
                ),
            );
        }
        if !thunk_terminated {
            return Err("The import thunk table exceeds the browser entry limit.".into());
        }
        descriptor_index += 1;
        descriptor_file += 20;
    }
    if !terminated {
        return Err(
            "The import descriptor table is not null-terminated within its directory.".into(),
        );
    }
    Ok(())
}

/*
This reader joins export functions, names, ordinals, and forwarders.
Malformed indexes or strings stop the complete structure request with an error.
*/
fn export_rows(
    pe: &BrowserPe,
    data: &[u8],
    rows: &mut Vec<(usize, String)>,
    limit: usize,
) -> Result<(), String> {
    /*
    The first section validates the export header and its three index tables.
    It also reads the module name for all output rows.
    */
    let Some(directory) = pe.directories[0] else {
        return Ok(());
    };
    if directory.size < 40 {
        return Err("The export directory is smaller than its header.".into());
    }
    let directory_file = pe.map_range(data, directory.rva, directory.size, "Export directory")?;
    let module_rva = browser_dword(data, directory_file + 12, "export directory")?;
    let ordinal_base = browser_dword(data, directory_file + 16, "export directory")?;
    let address_count = browser_dword(data, directory_file + 20, "export directory")?;
    let name_count = browser_dword(data, directory_file + 24, "export directory")?;
    let address_table_rva = browser_dword(data, directory_file + 28, "export directory")?;
    let name_table_rva = browser_dword(data, directory_file + 32, "export directory")?;
    let ordinal_table_rva = browser_dword(data, directory_file + 36, "export directory")?;
    let address_bytes = checked_count(address_count, 4, "export address")?;
    let name_bytes = checked_count(name_count, 4, "export name")?;
    let ordinal_bytes = checked_count(name_count, 2, "export ordinal")?;
    let address_count = address_count as usize;
    let name_count = name_count as usize;
    if name_count > address_count {
        return Err("The export name count exceeds the export address count.".into());
    }
    let (_, module) = pe.string_at_rva(data, module_rva, None, "export module name")?;
    let address_file = if address_bytes == 0 {
        None
    } else {
        Some(pe.map_range(
            data,
            address_table_rva,
            address_bytes as u32,
            "export address table",
        )?)
    };
    let name_file = if name_bytes == 0 {
        None
    } else {
        Some(pe.map_range(data, name_table_rva, name_bytes as u32, "export name table")?)
    };
    let ordinal_file = if ordinal_bytes == 0 {
        None
    } else {
        Some(pe.map_range(
            data,
            ordinal_table_rva,
            ordinal_bytes as u32,
            "export ordinal table",
        )?)
    };
    /*
    The name section joins each name pointer to its validated ordinal index.
    Unnamed address entries keep an empty name list.
    */
    let mut names = vec![Vec::<u32>::new(); address_count];
    for index in 0..name_count {
        let name_rva = browser_dword(data, name_file.unwrap() + index * 4, "export name pointer")?;
        let ordinal_index = usize::from(browser_word(
            data,
            ordinal_file.unwrap() + index * 2,
            "export ordinal",
        )?);
        if ordinal_index >= address_count {
            return Err("An export ordinal index exceeds the export address table.".into());
        }
        pe.string_at_rva(data, name_rva, None, "export name")?;
        names[ordinal_index].push(name_rva);
    }

    /*
    The row section resolves each nonzero target and detects forwarder strings.
    It creates one row for each name or one ordinal-only row.
    */
    let directory_end = u64::from(directory.rva) + u64::from(directory.size);
    for (index, entry_names) in names.iter().enumerate() {
        let entry_file = address_file.unwrap() + index * 4;
        let target_rva = browser_dword(data, entry_file, "export address")?;
        if target_rva == 0 {
            if !entry_names.is_empty() {
                return Err("A named export has a zero export address.".into());
            }
            continue;
        }
        let ordinal = ordinal_base
            .checked_add(index as u32)
            .ok_or("An export ordinal exceeds the address range.")?;
        let target_va = pe.va(target_rva, "export target")?;
        let (target_file, detail) = if u64::from(target_rva) >= u64::from(directory.rva)
            && u64::from(target_rva) < directory_end
        {
            let (file, forwarder) =
                pe.string_at_rva(data, target_rva, Some(directory_end), "export forwarder")?;
            (Some(file), format!(" Forwarder={forwarder}"))
        } else {
            (
                pe.virtual_file(data, target_rva, "export target")?,
                String::new(),
            )
        };
        let target_file = target_file.map_or_else(|| "-".into(), |file| format!("{file:08X}"));
        if entry_names.is_empty() {
            add_row(
                rows,
                limit,
                entry_file,
                format!(
                    "Export {module}!#{ordinal} | EntryFile={entry_file:08X} File={target_file} RVA={target_rva:08X} VA={target_va:016X}{detail}"
                ),
            );
        } else {
            for &name_rva in entry_names {
                if rows.len() >= limit {
                    break;
                }
                let (_, name) = pe.string_at_rva(data, name_rva, None, "export name")?;
                add_row(
                    rows,
                    limit,
                    entry_file,
                    format!(
                        "Export {module}!{name} | Ordinal={ordinal} EntryFile={entry_file:08X} File={target_file} RVA={target_rva:08X} VA={target_va:016X}{detail}"
                    ),
                );
            }
        }
    }
    Ok(())
}

/*
This entry point creates PE structure rows from current source bytes and applies the caller's row cap.
It adds rows by category: sections, directories, imports, exports, and overlay.
*/
pub fn structures(data: &[u8], limit: usize) -> Result<Vec<(usize, String)>, String> {
    let pe = BrowserPe::parse(data)?;
    let mut rows = Vec::with_capacity(limit.min(1_024));
    /*
    The first section creates one row for each mapped or virtual-only section.
    Each row carries a selectable source offset when source bytes exist.
    */
    for section in &pe.sections {
        let name = if section.name.is_empty() {
            "<unnamed>"
        } else {
            &section.name
        };
        let va = pe.va(section.rva, "section")?;
        if section.raw_size == 0 {
            add_row(
                &mut rows,
                limit,
                section.header,
                format!(
                    "Section {name} | File=- RVA={:08X} VA={va:016X} RawSize=00000000 VirtualSize={:08X} HeaderFile={:08X} Characteristics={:08X} | no raw bytes",
                    section.rva, section.virtual_size, section.header, section.characteristics
                ),
            );
        } else {
            add_row(
                &mut rows,
                limit,
                section.raw as usize,
                format!(
                    "Section {name} | File={:08X} RVA={:08X} VA={va:016X} RawSize={:08X} VirtualSize={:08X} Characteristics={:08X}",
                    section.raw,
                    section.rva,
                    section.raw_size,
                    section.virtual_size,
                    section.characteristics
                ),
            );
        }
    }
    /*
    The directory section keeps Security in its file-offset domain.
    All other directories use the PE virtual map.
    */
    for (index, directory) in pe.directories.iter().enumerate() {
        let Some(directory) = directory else {
            continue;
        };
        if index == 4 {
            add_row(
                &mut rows,
                limit,
                directory.rva as usize,
                format!(
                    "Directory Security | File={:08X} RVA=- VA=- Size={:08X} | certificate file offset",
                    directory.rva, directory.size
                ),
            );
        } else {
            let file = pe.map_range(data, directory.rva, directory.size, DIRECTORY_NAMES[index])?;
            let va = pe.va(directory.rva, DIRECTORY_NAMES[index])?;
            add_row(
                &mut rows,
                limit,
                file,
                format!(
                    "Directory {} | File={file:08X} RVA={:08X} VA={va:016X} Size={:08X}",
                    DIRECTORY_NAMES[index], directory.rva, directory.size
                ),
            );
        }
    }
    /*
    The table section appends imports and exports within the same row limit.
    A table error stops the complete browser request.
    */
    import_rows(&pe, data, &mut rows, limit)?;
    export_rows(&pe, data, &mut rows, limit)?;

    /*
    The final section finds bytes after all source-backed image ranges.
    One overlay row identifies the remaining file data.
    */
    let disk_end = pe
        .sections
        .iter()
        .try_fold(pe.header_size as usize, |end, section| {
            let section_end = (section.raw as usize)
                .checked_add(section.raw_size as usize)
                .ok_or("A section raw range exceeds the address range.")?;
            Ok::<_, String>(end.max(section_end))
        })?;
    if disk_end < data.len() {
        add_row(
            &mut rows,
            limit,
            disk_end,
            format!(
                "Overlay | File={disk_end:08X} RVA=- VA=- Size={:08X} | can contain certificate or debug data",
                data.len() - disk_end
            ),
        );
    }
    debug_assert!(rows.len() <= limit);
    debug_assert!(rows.iter().all(|(offset, _)| *offset < data.len()));
    Ok(rows)
}

/*
This entry point converts a checked PE address through current source bytes.
Partial mappings identify file gaps and virtual-only bytes without inventing unavailable domains.
*/
pub fn convert_address(data: &[u8], kind: AddressKind, value: u64) -> Result<PeAddress, String> {
    let pe = BrowserPe::parse(data)?;
    match kind {
        AddressKind::File => {
            let file =
                usize::try_from(value).map_err(|_| "The file offset exceeds the address range.")?;
            let rva = pe.file_rva(data, file, "file offset")?;
            let va = rva.map(|rva| pe.va(rva, "converted")).transpose()?;
            Ok(PeAddress {
                file_offset: Some(file),
                rva,
                va,
            })
        }
        AddressKind::Rva => {
            let rva = u32::try_from(value).map_err(|_| "The RVA exceeds the PE address range.")?;
            let file_offset = pe.virtual_file(data, rva, "converted address")?;
            let va = pe.va(rva, "converted")?;
            Ok(PeAddress {
                file_offset,
                rva: Some(rva),
                va: Some(va),
            })
        }
        AddressKind::Va => {
            if pe.bits == 32 && value > u64::from(u32::MAX) {
                return Err("The VA exceeds the PE32 address range.".into());
            }
            let rva = value
                .checked_sub(pe.image_base)
                .ok_or("The VA is below the PE image base.")?;
            let rva = u32::try_from(rva).map_err(|_| "The VA exceeds the PE address range.")?;
            let file_offset = pe.virtual_file(data, rva, "converted address")?;
            let va = pe.va(rva, "converted")?;
            Ok(PeAddress {
                file_offset,
                rva: Some(rva),
                va: Some(va),
            })
        }
    }
}

/*
This helper finds a PE signature through a checked DOS header offset.
Plain data returns no PE header, while malformed executable headers return an error.
*/
fn pe_header(data: &[u8]) -> Result<Option<usize>, String> {
    if data.starts_with(b"\x7fELF") || data.starts_with(b"NetWare Loadable Module\x1a") {
        return Err("This executable format is unsupported.".into());
    }
    if [b"NE", b"LE", b"LX"]
        .iter()
        .any(|magic| data.starts_with(*magic))
    {
        return Err("NE, LE, and LX executable formats are unsupported.".into());
    }
    if !data.starts_with(b"MZ") && !data.starts_with(b"ZM") {
        return Ok(None);
    }
    let header = dword(data, 60)? as usize;
    let signature = data.get(header..header + 4).unwrap_or(&[]);
    if signature == b"PE\0\0" {
        return Ok(Some(header));
    }
    if [b"NE", b"LE", b"LX"]
        .iter()
        .any(|magic| signature.starts_with(*magic))
    {
        return Err("NE, LE, and LX executable formats are unsupported.".into());
    }
    Ok(None)
}

/*
This standalone entry query maps the current PE entry RVA to a file offset.
Plain sources retain their existing zero entry, and DOS files retain their legacy entry calculation.
*/
pub fn entry_point(data: &[u8]) -> Result<u64, String> {
    if let Some(header) = pe_header(data)? {
        let pe = Pe::read(data, header)?;
        return pe
            .rva_to_file(pe.entry)
            .filter(|v| *v != u32::MAX)
            .map(u64::from)
            .ok_or_else(|| OUTSIDE.into());
    }
    if data.starts_with(b"MZ") || data.starts_with(b"ZM") {
        return Ok(u64::from(word(data, 20)?)
            + 16 * (u64::from(word(data, 8)?) + u64::from(word(data, 22)?)));
    }
    Ok(0)
}

/*
This standalone navigation wrapper maps one PE virtual address or RVA to a file offset.
Plain-source behavior and existing mapping errors remain unchanged.
*/
pub fn virtual_to_file(data: &[u8], address: u64) -> Result<u64, String> {
    match pe_header(data)? {
        Some(header) => Pe::read(data, header)?
            .virtual_to_file(address)
            .map(u64::from)
            .ok_or_else(|| OUTSIDE.into()),
        None => Ok(address),
    }
}

/*
This standalone tuple wrapper returns one current code address and compatibility width.
Callers that need the address domain use code_location instead.
*/
pub fn code_address(data: &[u8], file_offset: u64) -> Result<(u64, u32), String> {
    let location = code_location(data, file_offset)?;
    Ok((location.address, location.bits))
}

/*
This standalone helper parses the source and returns its complete CodeLocation.
Callers that retain the domain can distinguish file offsets from virtual addresses.
*/
pub fn code_location(data: &[u8], file_offset: u64) -> Result<CodeLocation, String> {
    Metadata::parse(data)?.code_location(file_offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    /*
    These fixture writers place little-endian values into preallocated PE buffers.
    Each test controls the destination range through fixed fixture offsets.
    */
    fn put_word(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_qword(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /*
    This fixture creates a minimal mapped PE32 or PE32+ source.
    Tests adjust selected header fields to exercise mapping errors.
    */
    fn fixture(plus: bool) -> Vec<u8> {
        let mut data = vec![0; 1024];
        data[..2].copy_from_slice(b"MZ");
        put(&mut data, 60, 128);
        data[128..132].copy_from_slice(b"PE\0\0");
        data[132..134].copy_from_slice(&(if plus { 34404u16 } else { 332u16 }).to_le_bytes());
        data[134] = 1;
        data[148] = if plus { 240 } else { 224 };
        let optional = 152;
        data[optional..optional + 2]
            .copy_from_slice(&(if plus { 0x20bu16 } else { 0x10bu16 }).to_le_bytes());
        put(&mut data, optional + 16, 4096);
        if plus {
            put(&mut data, optional + 24, 0x40000000);
            put(&mut data, optional + 28, 1);
        } else {
            put(&mut data, optional + 28, 0x400000);
        }
        put(&mut data, optional + 32, 4096);
        put(&mut data, optional + 36, 512);
        put(&mut data, optional + 56, 8192);
        put(&mut data, optional + 60, 512);
        let section = optional + if plus { 240 } else { 224 };
        put(&mut data, section + 8, 256);
        put(&mut data, section + 12, 4096);
        put(&mut data, section + 16, 512);
        put(&mut data, section + 20, 512);
        data
    }

    /*
    This fixture adds browser directories, imports, exports, names, and an overlay.
    The source keeps stable offsets for exact structure-row assertions.
    */
    fn browser_fixture(plus: bool) -> Vec<u8> {
        let mut data = fixture(plus);
        data.resize(0x810, 0);
        let optional = 152;
        let section = optional + if plus { 240 } else { 224 };
        data[section..section + 8].copy_from_slice(b".rdata\0\0");
        put(&mut data, section + 8, 0x600);
        put(&mut data, section + 16, 0x600);
        put(&mut data, section + 36, 0x4000_0040);
        put(&mut data, optional + if plus { 108 } else { 92 }, 16);
        let directories = optional + if plus { 112 } else { 96 };
        put(&mut data, directories, 0x1100);
        put(&mut data, directories + 4, 0xa0);
        put(&mut data, directories + 8, 0x1000);
        put(&mut data, directories + 12, 0x28);
        put(&mut data, directories + 32, 0x808);
        put(&mut data, directories + 36, 8);

        put(&mut data, 0x200, 0x1040);
        put(&mut data, 0x20c, 0x1080);
        put(&mut data, 0x210, 0x1060);
        if plus {
            put_qword(&mut data, 0x240, 0x1090);
            put_qword(&mut data, 0x248, 1u64 << 63 | 7);
            put_qword(&mut data, 0x260, 0x1090);
            put_qword(&mut data, 0x268, 1u64 << 63 | 7);
        } else {
            put(&mut data, 0x240, 0x1090);
            put(&mut data, 0x244, 1u32 << 31 | 7);
            put(&mut data, 0x260, 0x1090);
            put(&mut data, 0x264, 1u32 << 31 | 7);
        }
        data[0x280..0x28d].copy_from_slice(b"KERNEL32.dll\0");
        put_word(&mut data, 0x290, 0x1234);
        data[0x292..0x29e].copy_from_slice(b"ExitProcess\0");

        put(&mut data, 0x30c, 0x1140);
        put(&mut data, 0x310, 1);
        put(&mut data, 0x314, 3);
        put(&mut data, 0x318, 2);
        put(&mut data, 0x31c, 0x1128);
        put(&mut data, 0x320, 0x1134);
        put(&mut data, 0x324, 0x113c);
        put(&mut data, 0x328, 0x1170);
        put(&mut data, 0x32c, 0x1010);
        put(&mut data, 0x330, 0x1020);
        put(&mut data, 0x334, 0x1150);
        put(&mut data, 0x338, 0x1160);
        put_word(&mut data, 0x33c, 0);
        put_word(&mut data, 0x33e, 1);
        data[0x340..0x34c].copy_from_slice(b"fixture.dll\0");
        data[0x350..0x35a].copy_from_slice(b"Forwarded\0");
        data[0x360..0x366].copy_from_slice(b"Named\0");
        data[0x370..0x37d].copy_from_slice(b"OTHER.Target\0");
        data[0x800..0x810].copy_from_slice(b"TAILCERTIFICATE!");
        data
    }

    /*
    This helper adds one virtual-only section to an existing browser fixture.
    The returned section-table offset lets tests modify its fields.
    */
    fn add_zero_raw_section(data: &mut [u8], plus: bool) -> usize {
        put_word(data, 134, 2);
        let second = 152 + if plus { 240 } else { 224 } + 40;
        data[second..second + 8].copy_from_slice(b".bss\0\0\0\0");
        put(data, second + 8, 0x200);
        put(data, second + 12, 0x2000);
        put(data, second + 36, 0xc000_0080);
        second
    }

    /*
    This test checks PE32 and PE32+ entry and mapping vectors.
    Stale metadata remains usable after machine bytes change.
    A mapping request from newly parsed metadata rejects the changed machine.
    Incomplete data remains an error.
    */
    #[test]
    fn pe_mapping_vectors() {
        for plus in [false, true] {
            let data = fixture(plus);
            let base = if plus { 0x140000000 } else { 0x400000 };
            let bits = if plus { 64 } else { 32 };
            let metadata = Metadata::parse(&data).unwrap();
            assert_eq!(entry_point(&data), Ok(512));
            assert_eq!(virtual_to_file(&data, 4096 + 16), Ok(528));
            assert_eq!(virtual_to_file(&data, base + 4096 + 16), Ok(528));
            assert_eq!(virtual_to_file(&data, base + 128), Ok(128));
            assert_eq!(metadata.code_address(528), Ok((base + 4096 + 16, bits)));
            assert_eq!(metadata.code_address(128), Ok((base + 128, bits)));
            assert_eq!(
                metadata.code_location(528),
                Ok(CodeLocation {
                    address: base + 4096 + 16,
                    bits,
                    architecture: Architecture::X86(bits),
                    domain: AddressDomain::Va,
                })
            );
            assert!(metadata.code_address(1024).is_err());
            assert_eq!(virtual_to_file(&data, 4607), Ok(1023));
            assert!(virtual_to_file(&data, 4608).is_err());
            assert!(virtual_to_file(&data, u64::MAX).is_err());
            assert!(entry_point(&data[..400]).is_err());
        }
        let mut changed = fixture(false);
        let stale = Metadata::parse(&changed).unwrap();
        changed[132..134].copy_from_slice(&0u16.to_le_bytes());
        assert!(stale.code_address(512).is_ok());
        assert!(
            Metadata::parse(&changed)
                .unwrap()
                .code_address(512)
                .is_err()
        );
        let mut data = fixture(false);
        put(&mut data, 396, 513);
        assert_eq!(entry_point(&data), Ok(512));
        put(&mut data, 180, 1024);
        assert_eq!(virtual_to_file(&data, 4096), Ok(512));
        put(&mut data, 184, 512);
        assert_eq!(entry_point(&data), Ok(4096));
        put(&mut data, 184, 4096);
        put(&mut data, 396, 0);
        assert!(entry_point(&data).is_err());
        data[134] = 0;
        assert_eq!(entry_point(&data), Ok(4096));
    }

    /*
    This test checks plain-source file locations and legacy non-PE entry behavior.
    Malformed executable headers remain errors.
    */
    #[test]
    fn raw_and_invalid_vectors() {
        assert_eq!(entry_point(b"raw bytes"), Ok(0));
        assert_eq!(virtual_to_file(b"raw bytes", 16), Ok(16));
        assert_eq!(code_address(b"raw bytes", 16), Ok((16, 16)));
        assert_eq!(
            code_location(b"raw bytes", 16),
            Ok(CodeLocation {
                address: 16,
                bits: 16,
                architecture: Architecture::X86(16),
                domain: AddressDomain::File,
            })
        );
        assert_eq!(code_address(b"\x7fELF raw x86", 4), Ok((4, 16)));
        assert!(entry_point(b"\x7fELF").is_err());
        assert!(entry_point(b"MZ").is_err());
        let mut dos = vec![0; 64];
        dos[..2].copy_from_slice(b"MZ");
        dos[8] = 4;
        dos[20] = 2;
        dos[22] = 1;
        assert_eq!(entry_point(&dos), Ok(82));
    }

    /*
    This test checks explicit raw virtual addresses for every supported x86 width.
    The raw model overrides PE metadata and has no RVA domain.
    */
    #[test]
    fn explicit_raw_metadata_overrides_pe_and_maps_all_x86_widths() {
        let data = fixture(false);
        let parsed = Metadata::parse(&data).unwrap();
        assert_eq!(parsed.code_address(0x210), Ok((0x40_1010, 32)));

        for (bits, base) in [
            (16, 0x1000),
            (32, u64::from(u32::MAX) - data.len() as u64 + 1),
            (64, u64::MAX - data.len() as u64 + 1),
        ] {
            let metadata = Metadata::raw(base, bits).unwrap();
            assert_eq!(metadata.code_address(0x210), Ok((base + 0x210, bits)));
            assert_eq!(
                metadata.code_location(0x210),
                Ok(CodeLocation {
                    address: base + 0x210,
                    bits,
                    architecture: Architecture::X86(bits),
                    domain: AddressDomain::Va,
                })
            );
            assert_eq!(metadata.navigation_address(&data, 0), Ok(base));
            assert_eq!(metadata.navigation_offset(&data, base), Ok(0));
            assert_eq!(
                metadata.convert_address(&data, AddressKind::File, 0x210),
                Ok(PeAddress {
                    file_offset: Some(0x210),
                    rva: None,
                    va: Some(base + 0x210),
                })
            );
            assert_eq!(
                metadata.convert_address(&data, AddressKind::Va, base + 0x210),
                Ok(PeAddress {
                    file_offset: Some(0x210),
                    rva: None,
                    va: Some(base + 0x210),
                })
            );
            assert!(
                metadata
                    .convert_address(&data, AddressKind::Rva, 0)
                    .is_err()
            );
        }
    }

    /*
    This test checks shared architecture widths, alignment, and instruction-size limits.
    These facts do not enable the unsupported ARM decoder and assembler engines.
    */
    #[test]
    fn architecture_contract_validates_widths_alignment_and_lengths() {
        for bits in [16, 32, 64] {
            let architecture = Architecture::x86(bits).unwrap();
            assert_eq!(architecture.bits(), bits);
            assert_eq!(architecture.alignment(), 1);
            assert_eq!(architecture.max_instruction_bytes(), 15);
            assert!(architecture.valid_instruction_bytes(1));
            assert!(architecture.valid_instruction_bytes(15));
            assert!(!architecture.valid_instruction_bytes(0));
            assert!(!architecture.valid_instruction_bytes(16));
        }
        assert!(Architecture::x86(8).is_err());
        assert_eq!(
            (Architecture::Arm.bits(), Architecture::Arm.alignment()),
            (32, 4)
        );
        assert_eq!(
            (Architecture::Thumb.bits(), Architecture::Thumb.alignment()),
            (32, 2)
        );
        assert_eq!(
            (Architecture::Arm64.bits(), Architecture::Arm64.alignment()),
            (64, 4)
        );
        assert!(Architecture::Arm.valid_instruction_bytes(4));
        assert!(!Architecture::Arm.valid_instruction_bytes(2));
        assert!(Architecture::Thumb.valid_instruction_bytes(2));
        assert!(Architecture::Thumb.valid_instruction_bytes(4));
        assert!(!Architecture::Thumb.valid_instruction_bytes(3));
        assert!(Architecture::Arm64.valid_instruction_bytes(4));
    }

    /*
    This test checks raw width validation, address overflow, and current file bounds.
    Failed operations return before a caller can use an invalid model.
    */
    #[test]
    fn explicit_raw_metadata_checks_width_overflow_and_file_bounds() {
        assert!(Metadata::raw(0, 8).is_err());
        for bits in [16, 32] {
            let metadata = Metadata::raw(u64::from(u32::MAX), bits).unwrap();
            assert_eq!(metadata.code_address(0), Ok((u64::from(u32::MAX), bits)));
            assert!(metadata.code_address(1).is_err());
            assert!(Metadata::raw(u64::from(u32::MAX) + 1, bits).is_err());
        }
        let metadata = Metadata::raw(u64::MAX, 64).unwrap();
        assert_eq!(metadata.code_address(0), Ok((u64::MAX, 64)));
        assert!(metadata.code_address(1).is_err());

        let metadata = Metadata::raw(0x1000, 32).unwrap();
        let mut data = vec![0x90];
        assert_eq!(metadata.navigation_address(&data, 0), Ok(0x1000));
        assert_eq!(metadata.navigation_offset(&data, 0x1000), Ok(0));
        assert!(metadata.navigation_offset(&data, 0x0fff).is_err());
        assert!(metadata.navigation_address(&data, 1).is_err());
        assert!(metadata.navigation_offset(&data, 0x1001).is_err());
        assert!(
            metadata
                .convert_address(&data, AddressKind::File, 1)
                .is_err()
        );
        assert!(
            metadata
                .convert_address(&data, AddressKind::Va, 0x1001)
                .is_err()
        );

        data.push(0xc3);
        assert_eq!(metadata.navigation_address(&data, 1), Ok(0x1001));
        assert_eq!(metadata.navigation_offset(&data, 0x1001), Ok(1));
        data.clear();
        assert!(metadata.navigation_address(&data, 0).is_err());
        assert!(
            metadata
                .convert_address(&data, AddressKind::File, 0)
                .is_err()
        );
    }

    /*
    This test maps equivalent file, RVA, and virtual addresses for PE32 and PE32+.
    Boundary values outside the mapped section remain errors.
    */
    #[test]
    fn checked_address_conversion_maps_pe32_and_pe32_plus() {
        for plus in [false, true] {
            let data = fixture(plus);
            let base = if plus { 0x1_4000_0000 } else { 0x40_0000 };
            for (kind, value) in [
                (AddressKind::File, 0x210),
                (AddressKind::Rva, 0x1010),
                (AddressKind::Va, base + 0x1010),
            ] {
                assert_eq!(
                    convert_address(&data, kind, value),
                    Ok(PeAddress {
                        file_offset: Some(0x210),
                        rva: Some(0x1010),
                        va: Some(base + 0x1010),
                    })
                );
            }
            for (kind, value) in [
                (AddressKind::File, 0x80),
                (AddressKind::Rva, 0x80),
                (AddressKind::Va, base + 0x80),
            ] {
                assert_eq!(
                    convert_address(&data, kind, value),
                    Ok(PeAddress {
                        file_offset: Some(0x80),
                        rva: Some(0x80),
                        va: Some(base + 0x80),
                    })
                );
            }
            assert_eq!(
                convert_address(&data, AddressKind::File, 0x3ff),
                Ok(PeAddress {
                    file_offset: Some(0x3ff),
                    rva: Some(0x11ff),
                    va: Some(base + 0x11ff),
                })
            );
            assert_eq!(
                convert_address(&data, AddressKind::Rva, 0x11ff),
                Ok(PeAddress {
                    file_offset: Some(0x3ff),
                    rva: Some(0x11ff),
                    va: Some(base + 0x11ff),
                })
            );
            assert!(convert_address(&data, AddressKind::File, 0x400).is_err());
            assert!(convert_address(&data, AddressKind::Rva, 0x1200).is_err());
        }
    }

    /*
    This test checks navigation through mapped PE, raw, and current ELF-fallback sources.
    It preserves source bounds and unsupported PE-machine errors.
    */
    #[test]
    fn code_navigation_uses_checked_pe_raw_and_elf_mappings() {
        for plus in [false, true] {
            let data = fixture(plus);
            let base = if plus { 0x1_4000_0000 } else { 0x40_0000 };
            let metadata = Metadata::parse(&data).unwrap();
            assert_eq!(metadata.navigation_address(&data, 0x210), Ok(base + 0x1010));
            assert_eq!(metadata.navigation_offset(&data, base + 0x1010), Ok(0x210));
            assert!(
                metadata
                    .navigation_address(&data, data.len() as u64)
                    .is_err()
            );
            assert!(metadata.navigation_offset(&data, base + 0x1200).is_err());
        }

        for data in [&b"raw code"[..], &b"\x7fELF raw code"[..]] {
            let metadata = Metadata::parse(data).unwrap();
            assert_eq!(metadata.navigation_address(data, 4), Ok(4));
            assert_eq!(metadata.navigation_offset(data, 4), Ok(4));
            assert!(
                metadata
                    .navigation_address(data, data.len() as u64)
                    .is_err()
            );
            assert!(metadata.navigation_offset(data, data.len() as u64).is_err());
        }

        let overlay = browser_fixture(false);
        let metadata = Metadata::parse(&overlay).unwrap();
        assert!(metadata.navigation_address(&overlay, 0x800).is_err());

        let mut gap = fixture(false);
        gap.resize(0x500, 0);
        put(&mut gap, 376 + 20, 0x300);
        let metadata = Metadata::parse(&gap).unwrap();
        assert!(metadata.navigation_address(&gap, 0x250).is_err());

        let mut zero_fill = browser_fixture(false);
        add_zero_raw_section(&mut zero_fill, false);
        let metadata = Metadata::parse(&zero_fill).unwrap();
        assert!(metadata.navigation_offset(&zero_fill, 0x40_2010).is_err());

        let mut malformed = vec![0; 64];
        malformed[..2].copy_from_slice(b"MZ");
        let metadata = Metadata::parse(&malformed).unwrap();
        assert!(metadata.navigation_address(&malformed, 0).is_err());
        assert!(metadata.navigation_offset(&malformed, 0).is_err());

        let mut unsupported = fixture(false);
        put(&mut unsupported, 132, 0x01c4);
        let metadata = Metadata::parse(&unsupported).unwrap();
        assert_eq!(
            metadata.navigation_address(&unsupported, 0x210),
            Err("The PE processor is unsupported for code decoding.".into())
        );
    }

    /*
    This test reports file gaps, overlays, and virtual-only PE bytes as partial mappings.
    No unavailable address domain receives an invented value.
    */
    #[test]
    fn checked_address_conversion_reports_partial_mappings() {
        let mut gap = fixture(false);
        gap.resize(0x500, 0);
        put(&mut gap, 376 + 20, 0x300);
        assert_eq!(
            convert_address(&gap, AddressKind::File, 0x250),
            Ok(PeAddress {
                file_offset: Some(0x250),
                rva: None,
                va: None,
            })
        );

        let overlay = browser_fixture(false);
        for file_offset in [0x800, 0x808] {
            assert_eq!(
                convert_address(&overlay, AddressKind::File, file_offset as u64),
                Ok(PeAddress {
                    file_offset: Some(file_offset),
                    rva: None,
                    va: None,
                })
            );
        }

        let mut section_security = browser_fixture(false);
        put(&mut section_security, 152 + 96 + 32, 0x600);
        assert_eq!(
            convert_address(&section_security, AddressKind::File, 0x600),
            Ok(PeAddress {
                file_offset: Some(0x600),
                rva: Some(0x1400),
                va: Some(0x40_1400),
            })
        );

        let mut zero_fill = browser_fixture(false);
        add_zero_raw_section(&mut zero_fill, false);
        for (kind, value) in [(AddressKind::Rva, 0x2010), (AddressKind::Va, 0x40_2010)] {
            assert_eq!(
                convert_address(&zero_fill, kind, value),
                Ok(PeAddress {
                    file_offset: None,
                    rva: Some(0x2010),
                    va: Some(0x40_2010),
                })
            );
        }
        assert_eq!(
            convert_address(&zero_fill, AddressKind::Rva, 0x21ff),
            Ok(PeAddress {
                file_offset: None,
                rva: Some(0x21ff),
                va: Some(0x40_21ff),
            })
        );
        assert!(convert_address(&zero_fill, AddressKind::Rva, 0x2200).is_err());
    }

    /*
    This test rejects offsets, counts, and overlapping ranges that make PE mappings ambiguous.
    Each error identifies the invalid mapping class.
    */
    #[test]
    fn checked_address_conversion_rejects_invalid_ranges() {
        let data = fixture(false);
        for (kind, value) in [
            (AddressKind::File, data.len() as u64),
            (AddressKind::Rva, u64::from(u32::MAX) + 1),
            (AddressKind::Va, 0x3f_ffff),
            (AddressKind::Va, u64::from(u32::MAX) + 1),
        ] {
            assert!(convert_address(&data, kind, value).is_err());
        }
        assert!(convert_address(b"raw bytes", AddressKind::File, 0).is_err());
        assert!(convert_address(b"MZ", AddressKind::File, 0).is_err());

        let mut raw_header_overlap = fixture(false);
        put(&mut raw_header_overlap, 376 + 20, 0x100);
        assert!(
            convert_address(&raw_header_overlap, AddressKind::File, 0x180)
                .unwrap_err()
                .contains("raw range overlaps")
        );

        let mut rva_header_overlap = fixture(false);
        put(&mut rva_header_overlap, 376 + 12, 0x100);
        assert!(
            convert_address(&rva_header_overlap, AddressKind::Rva, 0x180)
                .unwrap_err()
                .contains("virtual range overlaps")
        );

        let mut raw_section_overlap = browser_fixture(false);
        let second = add_zero_raw_section(&mut raw_section_overlap, false);
        put(&mut raw_section_overlap, second + 16, 0x100);
        put(&mut raw_section_overlap, second + 20, 0x300);
        assert!(
            convert_address(&raw_section_overlap, AddressKind::File, 0x300)
                .unwrap_err()
                .contains("raw ranges overlap")
        );

        let mut rva_section_overlap = browser_fixture(false);
        let second = add_zero_raw_section(&mut rva_section_overlap, false);
        put(&mut rva_section_overlap, second + 12, 0x1100);
        assert!(
            convert_address(&rva_section_overlap, AddressKind::Rva, 0x1100)
                .unwrap_err()
                .contains("virtual ranges overlap")
        );

        let mut raw_outside = fixture(false);
        put(&mut raw_outside, 376 + 16, 0x201);
        assert!(
            convert_address(&raw_outside, AddressKind::File, 0x200)
                .unwrap_err()
                .contains("section raw data")
        );
    }

    /*
    This test reads the current image base and checks virtual-address addition.
    PE32 and PE32+ overflow returns an error.
    */
    #[test]
    fn checked_address_conversion_uses_current_image_base_and_checks_va_overflow() {
        let mut changed = fixture(false);
        put(&mut changed, 152 + 28, 0x50_0000);
        assert_eq!(
            convert_address(&changed, AddressKind::File, 0x210),
            Ok(PeAddress {
                file_offset: Some(0x210),
                rva: Some(0x1010),
                va: Some(0x50_1010),
            })
        );

        put(&mut changed, 152 + 28, 0xffff_f000);
        assert!(
            convert_address(&changed, AddressKind::Rva, 0x1000)
                .unwrap_err()
                .contains("PE32 address range")
        );

        let mut plus = fixture(true);
        put_qword(&mut plus, 152 + 24, u64::MAX);
        assert!(
            convert_address(&plus, AddressKind::Rva, 1)
                .unwrap_err()
                .contains("address range")
        );
    }

    /*
    This test lists bounded PE32 and PE32+ browser rows with stable source offsets.
    It checks sections, directories, imports, exports, forwarders, and overlays.
    */
    #[test]
    fn pe_browser_lists_checked_pe32_and_pe32_plus_structures() {
        assert_eq!(escaped(b"A\n\x1b"), r"A\n\x1b");
        for plus in [false, true] {
            let data = browser_fixture(plus);
            let rows = structures(&data, usize::MAX).unwrap();
            assert!(rows.iter().all(|(offset, _)| *offset < data.len()));
            for expected in [
                "Section .rdata | File=00000200",
                "Directory Export | File=00000300",
                "Directory Import | File=00000200",
                "Directory Security | File=00000808 RVA=- VA=-",
                "Import KERNEL32.dll!ExitProcess Hint=1234 | File=00000260",
                "Import KERNEL32.dll!#7 |",
                "Export fixture.dll!Forwarded |",
                "Forwarder=OTHER.Target",
                "Export fixture.dll!Named |",
                "Export fixture.dll!#3 |",
                "Overlay | File=00000800 RVA=- VA=- Size=00000010",
            ] {
                assert!(
                    rows.iter().any(|(_, text)| text.contains(expected)),
                    "missing {expected}"
                );
            }
            assert_eq!(structures(&data, 3).unwrap().len(), 3);
            assert!(structures(&data, 0).unwrap().is_empty());
        }
    }

    /*
    This test labels IAT fallback entries and sections without file bytes.
    The browser retains source offsets for selectable records.
    */
    #[test]
    fn pe_browser_labels_iat_fallback_and_virtual_only_bytes() {
        for plus in [false, true] {
            let mut data = browser_fixture(plus);
            put(&mut data, 0x200, 0);
            let second = add_zero_raw_section(&mut data, plus);
            put(&mut data, 0x330, 0x2010);
            let rows = structures(&data, usize::MAX).unwrap();
            assert!(rows.iter().any(|(offset, text)| {
                *offset == second
                    && text.starts_with("Section .bss | File=-")
                    && text.contains("no raw bytes")
            }));
            assert!(rows.iter().any(|(_, text)| {
                text.starts_with("Import KERNEL32.dll!ExitProcess")
                    && text.contains("Source=IAT-fallback")
            }));
            assert!(rows.iter().any(|(offset, text)| {
                *offset == 0x330
                    && text.starts_with("Export fixture.dll!#3")
                    && text.contains("EntryFile=00000330 File=- RVA=00002010")
            }));
        }
    }

    /*
    This test rejects malformed browser ranges, counts, ordinals, and strings.
    The complete structure request stops at the first invalid record.
    */
    #[test]
    fn pe_browser_rejects_malformed_ranges_counts_and_strings() {
        let mut cases = Vec::new();

        let mut raw_range = browser_fixture(false);
        put(&mut raw_range, 376 + 16, 0x700);
        cases.push((raw_range, "section raw data"));

        let mut security = browser_fixture(false);
        put(&mut security, 152 + 96 + 32, 0x900);
        cases.push((security, "Security directory"));

        let mut descriptor = browser_fixture(false);
        put(&mut descriptor, 152 + 96 + 12, 20);
        cases.push((descriptor, "not null-terminated"));

        let mut import_name = browser_fixture(false);
        put(&mut import_name, 0x20c, 0x15ff);
        import_name[0x7ff] = b'A';
        cases.push((import_name, "import DLL name"));

        let mut export_count = browser_fixture(false);
        put(&mut export_count, 0x314, MAX_BROWSER_ENTRIES as u32 + 1);
        cases.push((export_count, "browser limit"));

        let mut export_ordinal = browser_fixture(false);
        put_word(&mut export_ordinal, 0x33c, 3);
        cases.push((export_ordinal, "ordinal index"));

        let mut forwarder = browser_fixture(false);
        put(&mut forwarder, 0x328, 0x119f);
        forwarder[0x39f] = b'A';
        cases.push((forwarder, "export forwarder"));

        let mut overlap = browser_fixture(false);
        let second = add_zero_raw_section(&mut overlap, false);
        put(&mut overlap, second + 12, 0x1100);
        cases.push((overlap, "virtual ranges overlap"));

        for (data, expected) in cases {
            let error = structures(&data, usize::MAX).unwrap_err();
            assert!(error.contains(expected), "{error:?} lacks {expected:?}");
        }
        assert_eq!(
            structures(b"raw bytes", 10),
            Err("The file is not a PE file.".into())
        );
    }

    /*
    This test reads the tracked native DLL fixtures through the PE structure browser.
    The expected Capstone and Keystone exports prove that import and export rows remain available.
    */
    #[test]
    fn pe_browser_reads_tracked_native_dlls() {
        for (name, export) in [
            ("windows-capstone-5.0.9.dll", "cs_open"),
            ("windows-keystone-0.9.2.dll", "ks_open"),
        ] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name);
            let data = std::fs::read(path).unwrap();
            let rows = structures(&data, 100_000).unwrap();
            assert!(rows.iter().all(|(offset, _)| *offset < data.len()));
            assert!(rows.iter().any(|(_, text)| text.starts_with("Section ")));
            assert!(rows.iter().any(|(_, text)| text.starts_with("Import ")));
            assert!(
                rows.iter()
                    .any(|(_, text)| { text.starts_with("Export ") && text.contains(export) })
            );
        }
    }
}
