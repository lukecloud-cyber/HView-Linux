use std::fmt::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Text,
    Hex,
    Code,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawModel {
    pub base: u64,
    pub bits: u32,
    pub byte_order: ByteOrder,
}

impl RawModel {
    fn validate(self, file_len: usize) -> Result<(), String> {
        let last = u64::try_from(file_len.saturating_sub(1))
            .map_err(|_| "The raw file size exceeds the address range.")?;
        crate::format::Metadata::raw(self.base, self.bits)?.code_address(last)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Key {
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    PageUp,
    PageDown,
    FileStart,
    FileEnd,
}

pub struct Editor {
    pub data: Vec<u8>,
    pub offset: u64,
    pub top: u64,
    pub mode: Mode,
    pub editing: bool,
    pub dirty: bool,
    pub low_nibble: bool,
    pub text_column: usize,
    pub wrap: bool,
    pub expand_tabs: bool,
    pub delimiter: &'static [u8],
    pub hex_delimiter: char,
    pub is_text: bool,
    pub code_bits: u32,
    pub real_mode: bool,
    pub raw_model: Option<RawModel>,
    pub syntax: crate::decoder::Syntax,
    pub invalid_code_bytes: bool,
    pub opcode_bytes: usize,
    pub pack_nops: bool,
    pub pack_int3: bool,
    backup: Option<Vec<u8>>,
}

impl Editor {
    pub fn new(data: Vec<u8>, mode: Mode, offset: u64) -> Self {
        let mut offset = offset.min(data.len() as u64);
        if mode == Mode::Text {
            offset = text_start(&data, offset as usize, b"\r\n") as u64;
        }
        Self {
            data,
            offset,
            top: if mode == Mode::Text { offset } else { 0 },
            mode,
            editing: false,
            dirty: false,
            low_nibble: false,
            text_column: 0,
            wrap: true,
            expand_tabs: false,
            delimiter: b"\r\n",
            hex_delimiter: '-',
            is_text: false,
            code_bits: 16,
            real_mode: false,
            raw_model: None,
            syntax: crate::decoder::Syntax::Intel,
            invalid_code_bytes: false,
            opcode_bytes: 15,
            pack_nops: true,
            pack_int3: true,
            backup: None,
        }
    }

    pub fn set_raw_model(&mut self, raw_model: Option<RawModel>) -> Result<(), String> {
        if let Some(model) = raw_model {
            model.validate(self.data.len())?;
        }
        self.raw_model = raw_model;
        Ok(())
    }

    pub fn validate_raw_len(&self, new_len: usize) -> Result<(), String> {
        if let Some(model) = self.raw_model {
            model.validate(new_len)?;
        }
        Ok(())
    }

    pub fn decode_bits(&self) -> u32 {
        self.raw_model.map_or(self.code_bits, |model| model.bits)
    }

    pub fn decode_real_mode(&self) -> bool {
        self.raw_model.is_none() && self.real_mode
    }

    pub fn metadata(&self) -> Result<crate::format::Metadata, String> {
        match self.raw_model {
            Some(model) => {
                self.validate_raw_len(self.data.len())?;
                crate::format::Metadata::raw(model.base, model.bits)
            }
            None => crate::format::Metadata::parse(&self.data),
        }
    }

    pub fn convert_address(
        &self,
        kind: crate::format::AddressKind,
        value: u64,
    ) -> Result<crate::format::PeAddress, String> {
        self.metadata()?.convert_address(&self.data, kind, value)
    }

    pub fn goto(&mut self, offset: u64, rows: usize) {
        self.offset = offset.min(self.data.len() as u64);
        self.low_nibble = false;
        if self.mode == Mode::Text {
            self.top = text_start(&self.data, self.offset as usize, self.delimiter) as u64;
        } else {
            self.top = self.offset.saturating_sub(rows as u64 * 8) / 16 * 16;
            let file_rows = (self.data.len() as u64).div_ceil(16);
            self.top = self.top.min(file_rows.saturating_sub(rows as u64) * 16);
        }
    }

    pub fn toggle_edit(&mut self) -> Result<(), String> {
        if self.mode == Mode::Text {
            return Err("Editing is supported only in hex and code modes.".into());
        }
        if !self.editing {
            // ponytail: The backup uses one file-sized allocation. Use changed ranges for large files.
            self.backup = Some(self.data.clone());
            self.editing = true;
            self.low_nibble = false;
        }
        Ok(())
    }

    pub fn undo_current_byte(&mut self) {
        if let Some(original) = &self.backup {
            let index = self.offset as usize;
            if let (Some(old), Some(current)) = (original.get(index), self.data.get_mut(index)) {
                *current = *old;
                self.offset = (self.offset + 1).min(self.data.len() as u64);
                self.low_nibble = false;
                self.dirty = self.data != *original;
            }
        }
    }

    pub fn cancel_edit(&mut self) {
        if let Some(data) = self.backup.take() {
            self.data = data;
        }
        self.offset = self.offset.min(self.data.len() as u64);
        self.editing = false;
        self.dirty = false;
        self.low_nibble = false;
    }

    pub fn saved(&mut self) {
        self.backup = None;
        self.editing = false;
        self.dirty = false;
        self.low_nibble = false;
    }

    pub fn hex_digit(&mut self, c: char) -> Result<(), String> {
        if !self.editing || self.mode != Mode::Hex {
            return Err("Press F3 to enter hex edit mode.".into());
        }
        let digit = c.to_digit(16).ok_or("Enter a hexadecimal digit.")? as u8;
        let index =
            usize::try_from(self.offset).map_err(|_| "The offset exceeds the address range.")?;
        if index > self.data.len() {
            return Err("The offset exceeds the file size.".into());
        }
        if index == self.data.len() {
            let new_len = self
                .data
                .len()
                .checked_add(1)
                .ok_or("The edit buffer exceeds the address range.")?;
            self.validate_raw_len(new_len)?;
            self.data
                .try_reserve(1)
                .map_err(|_| "Cannot allocate the edit buffer.")?;
            self.data.push(0);
        }
        self.data[index] = replace_nibble(self.data[index], digit, self.low_nibble);
        if self.low_nibble {
            self.offset += 1;
        }
        self.low_nibble = !self.low_nibble;
        self.dirty = true;
        Ok(())
    }

    pub fn navigate(&mut self, key: Key, rows: usize, width: usize) {
        if self.mode == Mode::Text {
            self.navigate_text(key, rows, width);
            return;
        }
        if self.mode != Mode::Hex {
            return;
        }
        let size = self.data.len() as u64;
        let page = rows.max(1) as u64 * 16;
        match key {
            Key::Left if self.editing => {
                if !self.low_nibble {
                    self.offset = self.offset.saturating_sub(1);
                }
                self.low_nibble = !self.low_nibble;
            }
            Key::Right if self.editing => {
                if self.low_nibble {
                    self.offset = (self.offset + 1).min(size);
                }
                self.low_nibble = !self.low_nibble;
            }
            Key::Left => self.offset = self.offset.saturating_sub(1),
            Key::Right => self.offset = self.offset.saturating_add(1).min(size),
            Key::Up => {
                if self.offset >= 16 {
                    self.offset -= 16;
                }
            }
            Key::Down => {
                if self.offset.saturating_add(16) < size {
                    self.offset += 16;
                }
            }
            Key::Home => {
                self.offset = self.offset / 16 * 16;
                self.low_nibble = false;
            }
            Key::End => {
                self.offset = (self.offset / 16 * 16 + 15).min(size.saturating_sub(1));
                self.low_nibble = false;
            }
            Key::PageUp => {
                self.top = self.top.saturating_sub(page);
                self.offset = self.top + self.offset % 16;
            }
            Key::PageDown => {
                if self
                    .top
                    .saturating_add(page)
                    .saturating_add(self.offset % 16)
                    < size
                {
                    self.top += page;
                    self.offset = self.top + self.offset % 16;
                } else if size > 0 {
                    self.offset = (size / 16 * 16 + self.offset % 16).min(size.saturating_sub(1));
                }
            }
            Key::FileStart => {
                self.offset = 0;
                self.top = 0;
                self.low_nibble = false;
            }
            Key::FileEnd => {
                self.offset = size.saturating_sub(1);
                self.low_nibble = false;
            }
        }
        self.offset = self.offset.min(size);
        if self.offset < self.top {
            self.top = self.offset / 16 * 16;
        }
        if self.offset >= self.top.saturating_add(page) {
            self.top = (self.offset / 16 + 1).saturating_sub(rows.max(1) as u64) * 16;
        }
    }

    fn navigate_text(&mut self, key: Key, rows: usize, width: usize) {
        let line_width = if self.wrap { width.max(1) } else { 512 };
        match key {
            Key::Left => self.text_column = self.text_column.saturating_sub(1),
            Key::Right => {
                self.text_column = (self.text_column + 1).min(line_width.saturating_sub(width))
            }
            Key::Home => self.text_column = 0,
            Key::End => self.text_column = line_width.saturating_sub(width),
            Key::FileStart => self.top = 0,
            Key::FileEnd => self.top = self.data.len().saturating_sub(1) as u64,
            Key::Down | Key::PageDown => {
                for _ in 0..if matches!(key, Key::PageDown) {
                    rows.max(1)
                } else {
                    1
                } {
                    let (_, next) = text_line(
                        &self.data,
                        self.top as usize,
                        line_width,
                        self.expand_tabs,
                        self.delimiter,
                    );
                    if next < self.data.len() {
                        self.top = next as u64;
                    }
                }
            }
            Key::Up | Key::PageUp => {
                for _ in 0..if matches!(key, Key::PageUp) {
                    rows.max(1)
                } else {
                    1
                } {
                    // ponytail: Upward text navigation scans from the file start. Cache line offsets for large files.
                    let mut pos = 0;
                    let mut previous = 0;
                    while pos < self.top as usize {
                        previous = pos;
                        let (_, next) = text_line(
                            &self.data,
                            pos,
                            line_width,
                            self.expand_tabs,
                            self.delimiter,
                        );
                        if next <= pos || next >= self.top as usize {
                            break;
                        }
                        pos = next;
                    }
                    self.top = previous as u64;
                }
            }
        }
        self.offset = self.top;
    }

    pub fn render_body(&self, width: usize, rows: usize) -> Vec<String> {
        let mut output = Vec::with_capacity(rows);
        let mut pos = self.top.min(self.data.len() as u64) as usize;
        for row in 0..rows {
            let line = match self.mode {
                Mode::Hex => {
                    let address = self.top.saturating_add(row as u64 * 16);
                    if address < self.data.len() as u64 || address == self.offset {
                        hex_line_with_delimiter(&self.data, address, self.hex_delimiter)
                    } else {
                        String::new()
                    }
                }
                Mode::Text => {
                    let (line, next) = text_line(
                        &self.data,
                        pos,
                        if self.wrap { width.max(1) } else { 512 },
                        self.expand_tabs,
                        self.delimiter,
                    );
                    pos = next;
                    line.chars().skip(self.text_column).collect()
                }
                Mode::Code if row == 0 => "Code mode is not reconstructed.".into(),
                Mode::Code => String::new(),
            };
            output.push(line.chars().take(width).collect());
        }
        output
    }
}

pub fn replace_nibble(byte: u8, digit: u8, low: bool) -> u8 {
    if low {
        (byte & 0xf0) | (digit & 15)
    } else {
        (byte & 15) | ((digit & 15) << 4)
    }
}

#[cfg(test)]
pub fn hex_line(data: &[u8], offset: u64) -> String {
    hex_line_with_delimiter(data, offset, '-')
}

fn hex_line_with_delimiter(data: &[u8], offset: u64, delimiter: char) -> String {
    let mut line = format!(" {offset:08X}:  ");
    let data = usize::try_from(offset)
        .ok()
        .and_then(|pos| data.get(pos..))
        .unwrap_or_default();
    for i in 0..16 {
        if i > 0 {
            line.push(if i % 4 == 0 { delimiter } else { ' ' });
        }
        if let Some(byte) = data.get(i) {
            write!(line, "{byte:02X}").unwrap();
        } else {
            line.push_str("  ");
        }
    }
    line.push_str("  ");
    line.extend(data.iter().take(16).map(|&byte| cp437(byte)));
    line
}

fn text_start(data: &[u8], offset: usize, delimiter: &[u8]) -> usize {
    data[..offset]
        .windows(delimiter.len())
        .rposition(|pair| pair == delimiter)
        .map_or(0, |pos| pos + delimiter.len())
}

fn text_line(
    data: &[u8],
    start: usize,
    width: usize,
    tabs: bool,
    delimiter: &[u8],
) -> (String, usize) {
    let mut line = String::new();
    let mut pos = start.min(data.len());
    let mut column = 0;
    while pos < data.len() && column < width {
        if data[pos..].starts_with(delimiter) {
            return (line, pos + delimiter.len());
        }
        let byte = data[pos];
        pos += 1;
        if byte == b'\t' && tabs {
            let count = (8 - column % 8).min(width - column);
            line.extend(std::iter::repeat_n(' ', count));
            column += count;
        } else {
            line.push(cp437(byte));
            column += 1;
        }
    }
    if data
        .get(pos..)
        .is_some_and(|tail| tail.starts_with(b"\r\n"))
    {
        pos += 2;
    }
    (line, pos)
}

pub fn cp437(byte: u8) -> char {
    const LOW: &str = " ☺☻♥♦♣♠•◘○◙♂♀♪♫☼►◄↕‼¶§▬↨↑↓→←∟↔▲▼";
    const HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";
    match byte {
        0..=31 => LOW.chars().nth(byte as usize).unwrap(),
        32..=126 => byte as char,
        127 => '⌂',
        _ => HIGH.chars().nth(byte as usize - 128).unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovered_editor_contract() {
        let data: Vec<u8> = (0..64).collect();
        let mut editor = Editor::new(data.clone(), Mode::Hex, 0);
        assert_eq!(
            hex_line(&data, 0),
            " 00000000:  00 01 02 03-04 05 06 07-08 09 0A 0B-0C 0D 0E 0F   ☺☻♥♦♣♠•◘○◙♂♀♪♫☼"
        );
        editor.toggle_edit().unwrap();
        editor.hex_digit('4').unwrap();
        editor.hex_digit('1').unwrap();
        assert_eq!((editor.data[0], editor.offset), (0x41, 1));
        editor.offset = 0;
        editor.undo_current_byte();
        assert_eq!(editor.data[0], 0);
        assert_eq!(editor.offset, 1);
        assert!(editor.editing);
        let mut fitting = Editor::new((0..=255).collect(), Mode::Hex, 255);
        fitting.goto(255, 28);
        assert_eq!(fitting.top, 0);
        editor.cancel_edit();
        assert_eq!(editor.data, data);
        editor.toggle_edit().unwrap();
        editor.goto(64, 28);
        editor.hex_digit('f').unwrap();
        assert_eq!(editor.data.len(), 65);
        editor.cancel_edit();
        assert_eq!(editor.data, data);
        editor.goto(32, 28);
        let pattern = crate::operations::Pattern::exact(vec![0x21, 0x22]).unwrap();
        assert_eq!(
            pattern.find(&editor.data, editor.offset as usize, false),
            Some(33)
        );
        editor.goto(u64::MAX, 28);
        assert_eq!(editor.offset, 64);
        editor.navigate(Key::FileStart, 28, 119);
        editor.navigate(Key::Left, 28, 119);
        assert_eq!(editor.offset, 0);
        editor.navigate(Key::Down, 28, 119);
        assert_eq!(editor.offset, 16);
        assert_eq!(
            text_line(b"abc\r\ndef", 0, 119, false, b"\r\n"),
            ("abc".into(), 5)
        );
        assert_eq!(
            text_line(b"ab\tc", 0, 119, true, b"\r\n"),
            ("ab      c".into(), 4)
        );
        assert_eq!(text_line(b"abcde", 0, 3, false, b"\r\n"), ("abc".into(), 3));
        for byte in 0..=255 {
            assert_ne!(cp437(byte), '\0');
        }
    }

    #[test]
    fn raw_model_is_atomic_and_auto_restores_the_underlying_mode() {
        let mut editor = Editor::new(vec![0x90, 0xc3], Mode::Code, 0);
        editor.code_bits = 16;
        editor.real_mode = true;
        let raw = RawModel {
            base: 0x401000,
            bits: 32,
            byte_order: ByteOrder::Little,
        };
        editor.set_raw_model(Some(raw)).unwrap();
        assert_eq!(editor.raw_model, Some(raw));
        assert_eq!(editor.decode_bits(), 32);
        assert!(!editor.decode_real_mode());
        assert_eq!(
            editor.metadata().unwrap().code_address(1),
            Ok((0x401001, 32))
        );

        assert!(
            editor
                .set_raw_model(Some(RawModel {
                    base: u64::from(u32::MAX),
                    bits: 32,
                    byte_order: ByteOrder::Big,
                }))
                .is_err()
        );
        assert_eq!(editor.raw_model, Some(raw));

        editor.set_raw_model(None).unwrap();
        assert_eq!(editor.raw_model, None);
        assert_eq!(editor.decode_bits(), 16);
        assert!(editor.decode_real_mode());
    }

    #[test]
    fn raw_model_checks_empty_buffers_and_hex_growth_without_mutation() {
        let mut empty = Editor::new(Vec::new(), Mode::Code, 0);
        empty
            .set_raw_model(Some(RawModel {
                base: u64::from(u32::MAX),
                bits: 16,
                byte_order: ByteOrder::Little,
            }))
            .unwrap();
        assert!(
            empty
                .convert_address(crate::format::AddressKind::File, 0)
                .is_err()
        );

        for (base, bits) in [(u64::from(u32::MAX), 32), (u64::MAX, 64)] {
            let mut editor = Editor::new(vec![0x90], Mode::Hex, 1);
            let raw = RawModel {
                base,
                bits,
                byte_order: ByteOrder::Little,
            };
            editor.set_raw_model(Some(raw)).unwrap();
            editor.toggle_edit().unwrap();
            let before = editor.data.clone();

            assert!(editor.hex_digit('f').is_err());
            assert_eq!(editor.data, before);
            assert_eq!(editor.raw_model, Some(raw));
            assert_eq!(editor.offset, 1);
            assert!(!editor.low_nibble);
            assert!(!editor.dirty);
        }
    }
}
