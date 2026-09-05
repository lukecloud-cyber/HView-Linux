use std::{collections::VecDeque, fmt::Write};

const EDIT_HISTORY_LIMIT: usize = 256;
const EDIT_HISTORY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
struct EditCursor {
    offset: u64,
    top: u64,
    low_nibble: bool,
}

struct EditRecord {
    start: usize,
    before: Vec<u8>,
    after: Vec<u8>,
    before_len: usize,
    after_len: usize,
    before_cursor: EditCursor,
    after_cursor: EditCursor,
    hex_group: bool,
}

impl EditRecord {
    fn bytes(&self) -> usize {
        self.before.len() + self.after.len()
    }
}

fn history_size(before: usize, after: usize) -> Result<usize, String> {
    before
        .checked_add(after)
        .filter(|&bytes| bytes <= EDIT_HISTORY_BYTES)
        .ok_or("The edit exceeds the 64 MiB undo history limit.".into())
}

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
    undo_history: VecDeque<EditRecord>,
    redo_history: VecDeque<EditRecord>,
    history_bytes: usize,
    changed_bytes: usize,
    hex_start: Option<EditCursor>,
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
            undo_history: VecDeque::new(),
            redo_history: VecDeque::new(),
            history_bytes: 0,
            changed_bytes: 0,
            hex_start: None,
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

    fn cursor(&self) -> EditCursor {
        EditCursor {
            offset: self.offset,
            top: self.top,
            low_nibble: self.low_nibble,
        }
    }

    fn set_cursor(&mut self, cursor: EditCursor) {
        self.offset = cursor.offset.min(self.data.len() as u64);
        self.top = cursor.top.min(self.data.len() as u64);
        self.low_nibble = cursor.low_nibble;
    }

    fn close_hex_group(&mut self) {
        if let Some(record) = self.undo_history.back_mut() {
            record.hex_group = false;
        }
        self.hex_start = None;
    }

    pub fn end_hex_group(&mut self) {
        self.close_hex_group();
    }

    fn clear_edit_history(&mut self) {
        self.undo_history.clear();
        self.redo_history.clear();
        self.history_bytes = 0;
        self.hex_start = None;
    }

    fn difference_count(&self, start: usize, end: usize) -> usize {
        let Some(backup) = &self.backup else {
            return 0;
        };
        (start..end)
            .filter(|&index| self.data.get(index) != backup.get(index))
            .count()
    }

    fn apply_record_bytes(
        &mut self,
        start: usize,
        bytes: &[u8],
        len: usize,
        cursor: EditCursor,
        affected_end: usize,
    ) {
        let before = self.difference_count(start, affected_end);
        if len > self.data.len() {
            self.data.resize(len, 0);
        }
        self.data[start..start + bytes.len()].copy_from_slice(bytes);
        self.data.truncate(len);
        let after = self.difference_count(start, affected_end);
        self.changed_bytes = self.changed_bytes.saturating_sub(before) + after;
        self.dirty = self.changed_bytes != 0;
        self.set_cursor(cursor);
    }

    fn record_edit(
        &mut self,
        start: usize,
        replacement: Vec<u8>,
        before_cursor: EditCursor,
        after_cursor: EditCursor,
        hex_group: bool,
    ) -> Result<bool, String> {
        if !self.editing {
            return Err("Press F3 to enter edit mode.".into());
        }
        if replacement.is_empty() {
            return Err("An edit must replace at least one byte.".into());
        }
        if start > self.data.len() {
            return Err("The edit starts past the file end.".into());
        }
        let end = start
            .checked_add(replacement.len())
            .ok_or("The edit exceeds the address range.")?;
        let before_len = self.data.len();
        let after_len = before_len.max(end);
        if after_cursor.offset > after_len as u64 || after_cursor.top > after_len as u64 {
            return Err("The edit cursor exceeds the file size.".into());
        }
        self.validate_raw_len(after_len)?;
        let old_end = end.min(before_len);
        let source = &self.data[start..old_end];
        if before_len == after_len && source == replacement {
            return Ok(false);
        }
        let record_bytes = history_size(source.len(), replacement.len())?;
        let mut before = Vec::new();
        before
            .try_reserve_exact(source.len())
            .map_err(|_| "Cannot allocate the edit history.")?;
        before.extend_from_slice(source);
        if after_len > before_len {
            self.data
                .try_reserve(after_len - before_len)
                .map_err(|_| "Cannot allocate the edit buffer.")?;
        }
        self.undo_history
            .try_reserve(1)
            .map_err(|_| "Cannot allocate the edit history.")?;

        while let Some(record) = self.redo_history.pop_front() {
            self.history_bytes -= record.bytes();
        }
        self.close_hex_group();
        while self.undo_history.len() >= EDIT_HISTORY_LIMIT
            || self.history_bytes + record_bytes > EDIT_HISTORY_BYTES
        {
            let record = self.undo_history.pop_front().unwrap();
            self.history_bytes -= record.bytes();
        }
        let record = EditRecord {
            start,
            before,
            after: replacement,
            before_len,
            after_len,
            before_cursor,
            after_cursor,
            hex_group,
        };
        let affected_end = start + record.before.len().max(record.after.len());
        self.apply_record_bytes(start, &record.after, after_len, after_cursor, affected_end);
        self.history_bytes += record_bytes;
        self.undo_history.push_back(record);
        Ok(true)
    }

    pub fn replace_bytes(
        &mut self,
        start: usize,
        replacement: Vec<u8>,
        after: (u64, u64),
    ) -> Result<(), String> {
        let before = self.cursor();
        let result = self.record_edit(
            start,
            replacement,
            before,
            EditCursor {
                offset: after.0,
                top: after.1,
                low_nibble: false,
            },
            false,
        );
        if result.is_ok() {
            self.close_hex_group();
        }
        result.map(|_| ())
    }

    pub fn undo(&mut self) -> Result<bool, String> {
        let Some(record) = self.undo_history.back() else {
            return Ok(false);
        };
        self.validate_raw_len(record.before_len)?;
        if record.before_len > self.data.len() {
            self.data
                .try_reserve(record.before_len - self.data.len())
                .map_err(|_| "Cannot allocate the edit buffer.")?;
        }
        self.redo_history
            .try_reserve(1)
            .map_err(|_| "Cannot allocate the edit history.")?;
        self.close_hex_group();
        let record = self.undo_history.pop_back().unwrap();
        let affected_end = record.start + record.before.len().max(record.after.len());
        self.apply_record_bytes(
            record.start,
            &record.before,
            record.before_len,
            record.before_cursor,
            affected_end,
        );
        self.redo_history.push_back(record);
        Ok(true)
    }

    pub fn redo(&mut self) -> Result<bool, String> {
        let Some(record) = self.redo_history.back() else {
            return Ok(false);
        };
        self.validate_raw_len(record.after_len)?;
        if record.after_len > self.data.len() {
            self.data
                .try_reserve(record.after_len - self.data.len())
                .map_err(|_| "Cannot allocate the edit buffer.")?;
        }
        self.undo_history
            .try_reserve(1)
            .map_err(|_| "Cannot allocate the edit history.")?;
        self.close_hex_group();
        let record = self.redo_history.pop_back().unwrap();
        let affected_end = record.start + record.before.len().max(record.after.len());
        self.apply_record_bytes(
            record.start,
            &record.after,
            record.after_len,
            record.after_cursor,
            affected_end,
        );
        self.undo_history.push_back(record);
        Ok(true)
    }

    pub fn goto(&mut self, offset: u64, rows: usize) {
        self.close_hex_group();
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
            let mut backup = Vec::new();
            backup
                .try_reserve_exact(self.data.len())
                .map_err(|_| "Cannot allocate the edit backup.")?;
            backup.extend_from_slice(&self.data);
            self.backup = Some(backup);
            self.clear_edit_history();
            self.changed_bytes = 0;
            self.editing = true;
            self.low_nibble = false;
        }
        Ok(())
    }

    pub fn cancel_edit(&mut self) {
        if let Some(data) = self.backup.take() {
            self.data = data;
        }
        self.clear_edit_history();
        self.changed_bytes = 0;
        self.offset = self.offset.min(self.data.len() as u64);
        self.editing = false;
        self.dirty = false;
        self.low_nibble = false;
    }

    pub fn saved(&mut self) {
        self.backup = None;
        self.clear_edit_history();
        self.changed_bytes = 0;
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
        }
        let low_nibble = self.low_nibble;
        let before_cursor = self.hex_start.unwrap_or_else(|| self.cursor());
        let current = self.data.get(index).copied().unwrap_or(0);
        let replacement = replace_nibble(current, digit, low_nibble);
        let after_cursor = EditCursor {
            offset: self.offset + u64::from(low_nibble),
            top: self.top,
            low_nibble: !low_nibble,
        };
        let grouped = low_nibble
            && self
                .undo_history
                .back()
                .is_some_and(|record| record.hex_group && record.start == index);
        if grouped {
            let affected_end = index + 1;
            let before = self.difference_count(index, affected_end);
            if current != replacement {
                if index == self.data.len() {
                    self.data.push(0);
                }
                self.data[index] = replacement;
                let after = self.difference_count(index, affected_end);
                self.changed_bytes = self.changed_bytes.saturating_sub(before) + after;
                self.dirty = self.changed_bytes != 0;
            }
            let record = self.undo_history.back_mut().unwrap();
            record.after[0] = replacement;
            record.after_cursor = after_cursor;
            record.hex_group = false;
            self.set_cursor(after_cursor);
        } else if !self.record_edit(
            index,
            vec![replacement],
            before_cursor,
            after_cursor,
            !low_nibble,
        )? {
            self.set_cursor(after_cursor);
        }
        self.hex_start = (!low_nibble).then_some(before_cursor);
        Ok(())
    }

    pub fn navigate(&mut self, key: Key, rows: usize, width: usize) {
        self.close_hex_group();
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
        assert!(editor.undo().unwrap());
        assert_eq!(editor.data[0], 0);
        assert_eq!(editor.offset, 0);
        assert!(editor.redo().unwrap());
        assert_eq!((editor.data[0], editor.offset), (0x41, 1));
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

    #[test]
    fn edit_history_groups_nibbles_and_preserves_redo_on_noop() {
        let mut editor = Editor::new(vec![0x12], Mode::Hex, 0);
        editor.toggle_edit().unwrap();

        editor.hex_digit('1').unwrap();
        editor.hex_digit('3').unwrap();
        assert_eq!(editor.data, [0x13]);
        assert_eq!(editor.offset, 1);
        assert!(editor.undo().unwrap());
        assert_eq!(editor.data, [0x12]);
        assert_eq!(
            (editor.offset, editor.low_nibble, editor.dirty),
            (0, false, false)
        );

        editor.replace_bytes(0, vec![0x12], (1, 1)).unwrap();
        assert_eq!((editor.offset, editor.top), (0, 0));
        assert!(editor.redo().unwrap());
        assert_eq!(editor.data, [0x13]);
        assert_eq!(
            (editor.offset, editor.low_nibble, editor.dirty),
            (1, false, true)
        );

        editor.cancel_edit();
        editor.goto(0, 1);
        editor.toggle_edit().unwrap();
        editor.hex_digit('f').unwrap();
        assert_eq!((editor.data[0], editor.low_nibble), (0xf2, true));
        assert!(editor.undo().unwrap());
        assert_eq!(
            (editor.data[0], editor.offset, editor.low_nibble),
            (0x12, 0, false)
        );
        assert!(editor.redo().unwrap());
        assert_eq!(
            (editor.data[0], editor.offset, editor.low_nibble),
            (0xf2, 0, true)
        );
        editor.hex_digit('4').unwrap();
        assert!(editor.undo().unwrap());
        assert_eq!((editor.data[0], editor.low_nibble), (0xf2, true));
        assert!(editor.undo().unwrap());
        assert_eq!((editor.data[0], editor.low_nibble), (0x12, false));
    }

    #[test]
    fn range_history_handles_growth_dirty_state_and_raw_redo_rejection() {
        let mut editor = Editor::new(vec![0x90], Mode::Code, 1);
        editor.toggle_edit().unwrap();
        editor.replace_bytes(1, vec![0xc3], (2, 1)).unwrap();
        assert_eq!(editor.data, [0x90, 0xc3]);
        assert_eq!((editor.offset, editor.top, editor.dirty), (2, 1, true));

        assert!(editor.undo().unwrap());
        assert_eq!(editor.data, [0x90]);
        assert_eq!((editor.offset, editor.top, editor.dirty), (1, 0, false));
        editor
            .set_raw_model(Some(RawModel {
                base: u64::from(u32::MAX),
                bits: 32,
                byte_order: ByteOrder::Little,
            }))
            .unwrap();
        let state = (editor.data.clone(), editor.offset, editor.top, editor.dirty);
        assert!(editor.redo().is_err());
        assert_eq!(
            (editor.data.clone(), editor.offset, editor.top, editor.dirty),
            state
        );
        editor.set_raw_model(None).unwrap();
        assert!(editor.redo().unwrap());
        assert_eq!(editor.data, [0x90, 0xc3]);
        assert_eq!((editor.offset, editor.top, editor.dirty), (2, 1, true));

        assert!(editor.undo().unwrap());
        editor.replace_bytes(0, vec![0x91], (1, 0)).unwrap();
        assert!(!editor.redo().unwrap());
        editor.replace_bytes(0, vec![0x90], (1, 0)).unwrap();
        assert!(!editor.dirty);
        editor.saved();
        assert!(!editor.undo().unwrap());
        assert!(!editor.redo().unwrap());
    }

    #[test]
    fn edit_history_interrupts_hex_groups_and_evicts_oldest_records() {
        let mut editor = Editor::new(vec![0x12], Mode::Hex, 0);
        editor.toggle_edit().unwrap();
        editor.hex_digit('f').unwrap();
        editor.replace_bytes(0, vec![0xf2], (0, 0)).unwrap();
        assert!(editor.low_nibble);
        editor.hex_digit('4').unwrap();
        assert!(editor.undo().unwrap());
        assert_eq!((editor.data[0], editor.low_nibble), (0xf2, true));
        assert!(editor.undo().unwrap());
        assert_eq!((editor.data[0], editor.low_nibble), (0x12, false));

        editor.cancel_edit();
        editor.toggle_edit().unwrap();
        for index in 0..=EDIT_HISTORY_LIMIT {
            editor
                .replace_bytes(0, vec![if index % 2 == 0 { 1 } else { 0 }], (0, 0))
                .unwrap();
        }
        assert_eq!(editor.undo_history.len(), EDIT_HISTORY_LIMIT);
        for _ in 0..EDIT_HISTORY_LIMIT {
            assert!(editor.undo().unwrap());
        }
        assert_eq!(editor.data, [1]);
        assert!(!editor.undo().unwrap());
        assert!(history_size(1, EDIT_HISTORY_BYTES).is_err());
        editor.cancel_edit();
        assert_eq!(editor.data, [0x12]);
        assert!(!editor.undo().unwrap());
    }

    #[test]
    fn history_byte_limit_evicts_and_rejects_edits_atomically() {
        let size = EDIT_HISTORY_BYTES / 4;
        let mut editor = Editor::new(vec![0; size], Mode::Hex, 0);
        editor.toggle_edit().unwrap();
        for byte in [1, 2, 3] {
            editor.replace_bytes(0, vec![byte; size], (0, 0)).unwrap();
        }
        assert_eq!(editor.undo_history.len(), 2);
        assert_eq!(editor.history_bytes, EDIT_HISTORY_BYTES);
        assert!(editor.undo().unwrap());
        assert!(editor.data.iter().all(|&byte| byte == 2));
        assert!(editor.undo().unwrap());
        assert!(editor.data.iter().all(|&byte| byte == 1));
        assert!(!editor.undo().unwrap());
        drop(editor);

        let size = EDIT_HISTORY_BYTES / 2 + 1;
        let mut editor = Editor::new(vec![0; size], Mode::Hex, 0);
        editor.toggle_edit().unwrap();
        editor.replace_bytes(0, vec![1], (1, 0)).unwrap();
        assert!(editor.undo().unwrap());
        let history_bytes = editor.history_bytes;
        assert!(
            editor
                .replace_bytes(0, vec![2; size], (size as u64, 0))
                .is_err()
        );
        assert_eq!(editor.data.len(), size);
        assert!(editor.data.iter().all(|&byte| byte == 0));
        assert_eq!((editor.offset, editor.top, editor.dirty), (0, 0, false));
        assert!(editor.undo_history.is_empty());
        assert_eq!(editor.redo_history.len(), 1);
        assert_eq!(editor.history_bytes, history_bytes);
        assert!(editor.redo().unwrap());
        assert_eq!(editor.data[0], 1);
        assert_eq!((editor.offset, editor.top, editor.dirty), (1, 0, true));
        assert!(editor.undo().unwrap());
        assert!(editor.data.iter().all(|&byte| byte == 0));
        assert_eq!((editor.offset, editor.top, editor.dirty), (0, 0, false));
    }
}
