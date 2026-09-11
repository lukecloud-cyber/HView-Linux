/*
This module owns buffered file data, view state, editing, presentation helpers, and source revisions.
The Editor applies range transactions to complete buffered data and preserves exact cursor state in bounded history.
Each actual byte mutation changes the source revision so analysis callers can reject stale results.
Paged files use the related logical-layout owner in paged.rs.
*/
use std::sync::atomic::{AtomicU64, Ordering};
use std::{collections::VecDeque, fmt::Write};

use crate::analysis::SourceStamp;

/*
Buffered and paged editors share the Windows history limits.
The record limit bounds operation count, and the byte limit bounds retained byte copies.
*/
const EDIT_HISTORY_LIMIT: usize = 256;
const EDIT_HISTORY_BYTES: usize = 130 * 1024 * 1024;

/*
Each new buffered editor receives one process-local source identity.
The revision starts at zero and changes after each actual byte mutation.
*/
static NEXT_SOURCE_ID: AtomicU64 = AtomicU64::new(1);

/*
One buffered cursor snapshot contains the byte position, viewport, and Hex nibble selection.
History records use these values to restore the exact view around an operation.
*/
#[derive(Clone, Copy)]
struct EditCursor {
    offset: u64,
    top: u64,
    low_nibble: bool,
}

/*
One buffered history record stores the changed range before and after one transaction.
Separate lengths support growth and shrinkage while cursor fields restore the related view.
The group flag joins two Hex nibble inputs into one byte operation.
*/
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

/*
This record method reports the complete retained byte cost for history accounting.
The caller adds the result only after checked operation planning succeeds.
*/
impl EditRecord {
    /*
    This method adds the before and after byte vector lengths for one record.
    Buffered history planning uses the result for eviction and current byte accounting.
    */
    fn bytes(&self) -> usize {
        self.before.len() + self.after.len()
    }
}

/*
This helper checks one proposed buffered record against the shared 130 MiB byte limit.
An overflow or oversized result fails before editor data or history changes.
*/
fn history_size(before: usize, after: usize) -> Result<usize, String> {
    before
        .checked_add(after)
        .filter(|&bytes| bytes <= EDIT_HISTORY_BYTES)
        .ok_or("The edit exceeds the 130 MiB undo history limit.".into())
}

/*
Mode selects the current buffered presentation and command rules.
Text, Hex, and Code reuse the same byte buffer and common view state.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Text,
    Hex,
    Code,
}

/*
ByteOrder selects how the raw model interprets multi-byte values.
The configured value passes to the value inspector through workbench.rs.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    Little,
    Big,
}

/*
RawModel supplies an explicit base, architecture, and byte order for unformatted code.
Validation prevents a configured address range from exceeding the selected architecture width.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawModel {
    pub base: u64,
    pub architecture: crate::format::Architecture,
    pub byte_order: ByteOrder,
}

/*
Raw-model validation maps the final buffered byte through the selected address model.
The format module returns the precise range error before configuration changes.
*/
impl RawModel {
    /*
    This method checks the final file byte through the proposed raw address mapping.
    An empty buffer uses file offset zero, which maps to the configured runtime base.
    */
    fn validate(self, file_len: usize) -> Result<(), String> {
        let last = u64::try_from(file_len.saturating_sub(1))
            .map_err(|_| "The raw file size exceeds the address range.")?;
        crate::format::Metadata::raw_architecture(self.base, self.architecture)?
            .code_address(last)?;
        Ok(())
    }
}

/*
Key lists navigation actions after the console converts terminal input.
Editor navigation applies mode-specific movement and viewport correction for each action.
*/
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

/*
Editor owns the complete buffered bytes and all active view settings.
Public fields support the established main loop and session wrappers.
Private fields preserve the edit baseline, histories, byte accounting, Hex group state, and analysis stamp.
Future direct data replacement must call source_changed before analysis accepts another result.
*/
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
    source_identity: u64,
    revision: u64,
}

/*
These methods create the buffered editor and apply its navigation, rendering, and transaction rules.
Each mutation keeps byte data, cursor state, dirty state, and bounded history consistent.
*/
impl Editor {
    /*
    This constructor accepts owned bytes, an initial mode, and a requested byte offset.
    It clamps the offset and aligns Text mode to the current line start.
    Remaining settings receive the established Linux defaults before the main loop uses them.
    */
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
            source_identity: NEXT_SOURCE_ID.fetch_add(1, Ordering::Relaxed),
            revision: 0,
        }
    }

    /*
    This setter validates a proposed raw model against the current byte length.
    A failure preserves the previous model, and success publishes the new selection.
    */
    pub fn set_raw_model(&mut self, raw_model: Option<RawModel>) -> Result<(), String> {
        if let Some(model) = raw_model {
            model.validate(self.data.len())?;
        }
        self.raw_model = raw_model;
        Ok(())
    }

    /*
    This check validates a proposed byte length under the optional raw model.
    Edit planning calls the check before any growth changes the buffer.
    */
    pub fn validate_raw_len(&self, new_len: usize) -> Result<(), String> {
        if let Some(model) = self.raw_model {
            model.validate(new_len)?;
        }
        Ok(())
    }

    /*
    This query enables Real16 only when no raw model overrides normal Code settings.
    The decoder uses the result with the selected bit width.
    */
    pub fn decode_real_mode(&self) -> bool {
        self.raw_model.is_none() && self.real_mode
    }

    /*
    This method returns raw metadata or parses the current file format from buffered bytes.
    Raw metadata receives a fresh length check before address operations use it.
    */
    pub fn metadata(&self) -> Result<crate::format::Metadata, String> {
        match self.raw_model {
            Some(model) => {
                self.validate_raw_len(self.data.len())?;
                crate::format::Metadata::raw_architecture(model.base, model.architecture)
            }
            None => crate::format::Metadata::parse(&self.data),
        }
    }

    /*
    This method converts one user address through the current metadata and byte buffer.
    Format validation and mapping errors pass unchanged to the caller.
    */
    pub fn convert_address(
        &self,
        kind: crate::format::AddressKind,
        value: u64,
    ) -> Result<crate::format::PeAddress, String> {
        self.metadata()?.convert_address(&self.data, kind, value)
    }

    /*
    This helper captures the current position, viewport, and nibble selection.
    A new transaction stores the snapshot as its before cursor.
    */
    fn cursor(&self) -> EditCursor {
        EditCursor {
            offset: self.offset,
            top: self.top,
            low_nibble: self.low_nibble,
        }
    }

    /*
    This helper restores one cursor snapshot after a history operation.
    It clamps byte and viewport positions to the restored buffered length.
    */
    fn set_cursor(&mut self, cursor: EditCursor) {
        self.offset = cursor.offset.min(self.data.len() as u64);
        self.top = cursor.top.min(self.data.len() as u64);
        self.low_nibble = cursor.low_nibble;
    }

    /*
    This helper closes a pending two-nibble Hex group and clears its initial cursor.
    The retained record remains one complete undo operation.
    */
    fn close_hex_group(&mut self) {
        if let Some(record) = self.undo_history.back_mut() {
            record.hex_group = false;
        }
        self.hex_start = None;
    }

    /*
    This public boundary closes a pending Hex group before another user action.
    Main uses the method when a non-Hex command interrupts input.
    */
    pub fn end_hex_group(&mut self) {
        self.close_hex_group();
    }

    /*
    This reset removes both history branches and their byte accounting.
    Save, cancellation, and a new baseline call the reset together with related state changes.
    */
    fn clear_edit_history(&mut self) {
        self.undo_history.clear();
        self.redo_history.clear();
        self.history_bytes = 0;
        self.hex_start = None;
    }

    /*
    This helper counts bytes that differ from the edit baseline in one affected range.
    Transaction application uses the count to update dirty state without scanning the complete buffer.
    */
    fn difference_count(&self, start: usize, end: usize) -> usize {
        let Some(backup) = &self.backup else {
            return 0;
        };
        (start..end)
            .filter(|&index| self.data.get(index) != backup.get(index))
            .count()
    }

    /*
    This commit helper applies one prepared history side to the owned byte buffer.
    It grows before copying, truncates afterward, updates changed-byte accounting, and restores the cursor.
    Each caller reaches this helper only for an actual byte mutation, so the helper advances the source revision.
    All fallible allocation and model checks occur before this helper runs.
    */
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
        self.bump_revision();
    }

    /*
    This helper advances the current buffered byte-state revision after one real mutation.
    Wrapping preserves the upstream counter behavior without turning a mutation into a fallible operation.
    */
    fn bump_revision(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }

    /*
    This accessor captures the current process-local source identity and byte revision.
    Analysis results carry this value until the terminal acceptance check.
    */
    pub(crate) fn buffer_stamp(&self) -> SourceStamp {
        SourceStamp::new(self.source_identity, self.revision)
    }

    /*
    This action assigns a new source identity after successful external source adoption.
    Save As calls this action before saved clears the accepted edit session.
    */
    pub(crate) fn source_changed(&mut self) {
        self.source_identity = NEXT_SOURCE_ID.fetch_add(1, Ordering::Relaxed);
        self.revision = 0;
    }

    /*
    This transaction planner validates one fixed buffered replacement and prepares its history record.
    It completes range, cursor, model, history, and allocation checks before data changes.
    A real edit clears redo, evicts oldest records when necessary, applies bytes, and stores one undo record.
    */
    fn record_edit(
        &mut self,
        start: usize,
        replacement: Vec<u8>,
        before_cursor: EditCursor,
        after_cursor: EditCursor,
        hex_group: bool,
    ) -> Result<bool, String> {
        /*
        First, validate mode, range, resulting length, cursor bounds, and raw address limits.
        A byte-identical fixed replacement returns before history or data changes.
        */
        if !self.editing {
            return Err("Press Alt+E to enter edit mode.".into());
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
        /*
        Next, allocate the before bytes, any required buffer growth, and one undo slot.
        The editor still owns its unchanged data and both unchanged history branches.
        */
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

        /*
        Finally, clear redo and evict the oldest undo records within both limits.
        The prepared record then applies its after bytes and becomes the newest undo record.
        */
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

    /*
    This public wrapper captures the current cursor for one fixed buffered replacement.
    It closes any Hex group after successful planning, including a byte-identical no-op.
    */
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

    /*
    Undo validates restored length and reserves buffer or redo storage before mutation.
    It then applies the before bytes, restores the before cursor, and moves the record to redo.
    */
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

    /*
    Redo validates applied length and reserves buffer or undo storage before mutation.
    It then applies the after bytes, restores the after cursor, and moves the record to undo.
    */
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

    /*
    Goto closes Hex grouping and moves to a checked requested position.
    Text aligns to a line start, while Hex centers and clamps its row viewport.
    */
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

    /*
    This action starts buffered editing only in Hex or Code mode.
    It allocates an exact baseline before it clears history and changes edit state.
    */
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

    /*
    Cancellation restores the owned baseline and removes all buffered edit history.
    It clamps the cursor to restored data and returns the editor to clean normal mode.
    A restored byte change advances the revision, while an unchanged cancellation preserves the stamp.
    */
    pub fn cancel_edit(&mut self) {
        let changed = self.dirty;
        if let Some(data) = self.backup.take() {
            self.data = data;
        }
        self.clear_edit_history();
        self.changed_bytes = 0;
        self.offset = self.offset.min(self.data.len() as u64);
        self.editing = false;
        self.dirty = false;
        self.low_nibble = false;
        if changed {
            self.bump_revision();
        }
    }

    /*
    A successful save makes current bytes the new external baseline.
    It removes the old backup and history, then returns the editor to clean normal mode.
    This state reset does not change source identity or revision by itself.
    */
    pub fn saved(&mut self) {
        self.backup = None;
        self.clear_edit_history();
        self.changed_bytes = 0;
        self.editing = false;
        self.dirty = false;
        self.low_nibble = false;
    }

    /*
    Hex input converts one character and prepares the selected high or low nibble.
    A first nibble opens one record, and its matching second nibble completes that record.
    The method updates bytes, dirty accounting, cursor state, and group state together.
    */
    pub fn hex_digit(&mut self, c: char) -> Result<(), String> {
        /*
        First, validate edit mode, the digit, the current offset, and possible growth.
        The raw model check prevents an invalid appended byte before history changes.
        */
        if !self.editing || self.mode != Mode::Hex {
            return Err("Press Alt+E to enter Hex edit mode.".into());
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
        /*
        Next, calculate the replacement byte and the cursor after this nibble.
        The first-nibble cursor remains available until the byte group closes.
        */
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
        /*
        Finally, update the open record or create one new transaction.
        A byte-identical input still advances nibble state without a new history record.
        A changed grouped nibble advances the revision because it bypasses apply_record_bytes.
        */
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
                self.bump_revision();
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

    /*
    Navigation closes Hex grouping before it applies one mode-specific key.
    Text delegates to line movement, Code ignores these keys, and Hex updates byte or nibble position.
    Final correction keeps the selected Hex position inside the visible viewport.
    */
    pub fn navigate(&mut self, key: Key, rows: usize, width: usize) {
        self.close_hex_group();
        if self.mode == Mode::Text {
            self.navigate_text(key, rows, width);
            return;
        }
        if self.mode != Mode::Hex {
            return;
        }
        /*
        Hex movement uses the current logical size and one visible page size.
        Edit mode changes Left and Right from byte movement to nibble movement.
        */
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
        /*
        After movement, clamp the offset and adjust top only when the cursor leaves the viewport.
        This correction preserves its row position when possible.
        */
        self.offset = self.offset.min(size);
        if self.offset < self.top {
            self.top = self.offset / 16 * 16;
        }
        if self.offset >= self.top.saturating_add(page) {
            self.top = (self.offset / 16 + 1).saturating_sub(rows.max(1) as u64) * 16;
        }
    }

    /*
    Text navigation moves a horizontal column or one displayed row.
    A displayed row ends at the delimiter or the width limit.
    Page actions repeat line movement for the visible row count.
    The final offset follows the updated top because Text selects its first visible byte.
    */
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

    /*
    This renderer creates the requested visible body rows from current buffered state.
    Hex formats fixed byte rows, and Text advances displayed rows.
    This fallback shows a Code notice, while main.rs renders actual Code instructions.
    Every returned line is clipped to the terminal width.
    */
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

/*
This helper combines one hexadecimal digit with the selected nibble of a byte.
It preserves the other nibble and masks the input to four bits.
*/
pub fn replace_nibble(byte: u8, digit: u8, low: bool) -> u8 {
    if low {
        (byte & 0xf0) | (digit & 15)
    } else {
        (byte & 15) | ((digit & 15) << 4)
    }
}

#[cfg(test)]
/*
This test-only wrapper renders one standard Hex row with the default delimiter.
Unit tests compare the result with the recovered terminal format.
*/
pub fn hex_line(data: &[u8], offset: u64) -> String {
    hex_line_with_delimiter(data, offset, '-')
}

/*
This formatter builds one address, hexadecimal, and CP437 preview row.
The native u64 address stays visible even when the data slice has no matching usize position.
*/
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

/*
This helper finds the first byte of the Text line that contains the requested offset.
It searches the buffered prefix for the final configured delimiter.
*/
fn text_start(data: &[u8], offset: usize, delimiter: &[u8]) -> usize {
    data[..offset]
        .windows(delimiter.len())
        .rposition(|pair| pair == delimiter)
        .map_or(0, |pos| pos + delimiter.len())
}

/*
This formatter reads one buffered Text line from a checked start position.
It stops at the configured delimiter or width and can expand tabs to eight-column boundaries.
The returned next position feeds the following visible row.
*/
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

/*
This conversion maps each byte to the established CP437 display character.
ASCII stays direct, while fixed tables provide control glyphs and high characters.
*/
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
    /*
    These tests verify buffered view behavior, raw models, edit history, and presentation helpers.
    They use owned in-memory buffers and inspect private accounting within this module.
    */
    use super::*;

    /*
    This recovered contract test follows Hex editing, history, navigation, Text lines, and CP437 output.
    The sequence checks the established buffered behavior through its public methods.
    */
    #[test]
    fn recovered_editor_contract() {
        /*
        First, edit one Hex byte and verify its grouped history state.
        Cancellation and EOF growth then restore the exact original buffer.
        */
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
        /*
        Next, check search position, bounded Goto, and basic Hex navigation.
        These operations use the same offset state that history restores.
        */
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
        /*
        Finally, verify delimiter lines, tab expansion, clipping, and all CP437 byte mappings.
        These presentation checks consume the final buffered state without changing it.
        */
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

    /*
    This test verifies that raw-model selection is atomic and overrides normal Code settings.
    Removing the model restores the underlying width and Real16 selection.
    */
    #[test]
    fn raw_model_is_atomic_and_auto_restores_the_underlying_mode() {
        /*
        First, apply one valid raw model and verify its width and address mapping.
        The raw model temporarily overrides the normal Real16 setting.
        */
        let mut editor = Editor::new(vec![0x90, 0xc3], Mode::Code, 0);
        editor.code_bits = 16;
        editor.real_mode = true;
        let raw = RawModel {
            base: 0x401000,
            architecture: crate::format::Architecture::X86(32),
            byte_order: ByteOrder::Little,
        };
        editor.set_raw_model(Some(raw)).unwrap();
        assert_eq!(editor.raw_model, Some(raw));
        assert_eq!(
            editor
                .metadata()
                .unwrap()
                .decoder_architecture(editor.code_bits),
            Ok(crate::format::Architecture::X86(32))
        );
        assert!(!editor.decode_real_mode());
        assert_eq!(
            editor.metadata().unwrap().code_address(1),
            Ok((0x401001, 32))
        );

        /*
        Next, reject an invalid model and verify that the accepted model stays active.
        No byte or configuration state changes during the failed selection.
        */
        assert!(
            editor
                .set_raw_model(Some(RawModel {
                    base: u64::from(u32::MAX),
                    architecture: crate::format::Architecture::X86(32),
                    byte_order: ByteOrder::Big,
                }))
                .is_err()
        );
        assert_eq!(editor.raw_model, Some(raw));

        /*
        Finally, remove the raw model and expose the retained normal Code settings.
        */
        editor.set_raw_model(None).unwrap();
        assert_eq!(editor.raw_model, None);
        assert_eq!(
            editor
                .metadata()
                .unwrap()
                .decoder_architecture(editor.code_bits),
            Ok(crate::format::Architecture::X86(16))
        );
        assert!(editor.decode_real_mode());
    }

    /*
    This test checks empty raw mappings and rejects Hex growth beyond configured address ranges.
    Each failure preserves bytes, model, cursor, nibble state, and dirty state.
    */
    #[test]
    fn raw_model_checks_empty_buffers_and_hex_growth_without_mutation() {
        /*
        First, verify that empty raw metadata cannot map a nonexistent byte.
        */
        let mut empty = Editor::new(Vec::new(), Mode::Code, 0);
        empty
            .set_raw_model(Some(RawModel {
                base: u64::from(u32::MAX),
                architecture: crate::format::Architecture::X86(16),
                byte_order: ByteOrder::Little,
            }))
            .unwrap();
        assert!(
            empty
                .convert_address(crate::format::AddressKind::File, 0)
                .is_err()
        );

        /*
        Next, test 32-bit and 64-bit address overflow during one-byte Hex growth.
        Every rejected input keeps its complete editor state.
        */
        for (base, architecture) in [
            (u64::from(u32::MAX), crate::format::Architecture::X86(32)),
            (u64::from(u32::MAX), crate::format::Architecture::Arm),
            (u64::from(u32::MAX), crate::format::Architecture::Thumb),
            (u64::MAX, crate::format::Architecture::X86(64)),
            (u64::MAX, crate::format::Architecture::Arm64),
        ] {
            let mut editor = Editor::new(vec![0x90], Mode::Hex, 1);
            let raw = RawModel {
                base,
                architecture,
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

    /*
    This test rejects invalid architecture selection and raw growth during an unsaved transaction.
    Each failure preserves bytes, cursor state, dirty state, and available Undo or Redo operations.
    */
    #[test]
    fn raw_architecture_rejection_preserves_the_complete_edit_transaction() {
        /*
        The setup creates two edit records and undoes only the second record.
        The snapshot therefore contains dirty bytes and one available operation in each history direction.
        */
        let original = vec![0x90, 0x90];
        let mut editor = Editor::new(original.clone(), Mode::Code, 0);
        editor.toggle_edit().unwrap();
        editor.replace_bytes(0, vec![0x91], (1, 0)).unwrap();
        editor.replace_bytes(1, vec![0x92], (2, 0)).unwrap();
        assert!(editor.undo().unwrap());
        assert_eq!(editor.data, [0x91, 0x90]);
        assert!(editor.dirty);
        let raw = RawModel {
            base: u64::from(u32::MAX) - 1,
            architecture: crate::format::Architecture::Arm,
            byte_order: ByteOrder::Big,
        };
        editor.set_raw_model(Some(raw)).unwrap();
        let state = (
            editor.data.clone(),
            editor.offset,
            editor.top,
            editor.low_nibble,
            editor.dirty,
            editor.raw_model,
            editor.undo_history.len(),
            editor.redo_history.len(),
            editor.history_bytes,
        );

        /*
        The rejection section requests one invalid architecture and one excessive growth operation.
        Both errors must preserve the complete snapshot from the active transaction.
        */
        assert!(
            editor
                .set_raw_model(Some(RawModel {
                    base: 0,
                    architecture: crate::format::Architecture::X86(8),
                    byte_order: ByteOrder::Little,
                }))
                .is_err()
        );
        assert!(editor.replace_bytes(2, vec![0, 0, 0, 0], (6, 0)).is_err());
        assert_eq!(
            (
                editor.data.clone(),
                editor.offset,
                editor.top,
                editor.low_nibble,
                editor.dirty,
                editor.raw_model,
                editor.undo_history.len(),
                editor.redo_history.len(),
                editor.history_bytes,
            ),
            state
        );

        /*
        The final section proves that Redo and both Undo records remain usable after the errors.
        Cancellation restores the independent original bytes and retains the valid raw model.
        */
        assert!(editor.redo().unwrap());
        assert_eq!(editor.data, [0x91, 0x92]);
        assert!(editor.undo().unwrap());
        assert_eq!(editor.data, [0x91, 0x90]);
        assert!(editor.undo().unwrap());
        assert_eq!(editor.data, original);
        editor.cancel_edit();
        assert_eq!(editor.data, original);
        assert_eq!(editor.raw_model, Some(raw));
    }

    /*
    This test joins two Hex nibbles and verifies exact cursor restoration through undo and redo.
    It also checks that a byte-identical replacement preserves redo history.
    */
    #[test]
    fn edit_history_groups_nibbles_and_preserves_redo_on_noop() {
        /*
        First, complete one two-nibble byte and verify undo and redo cursor state.
        A byte-identical operation after undo must retain the redo record.
        */
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

        /*
        Next, undo and redo an incomplete first nibble.
        A later low nibble creates a separate record after the history action closes grouping.
        */
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

    /*
    This test restores structural growth, dirty state, and cursors through buffered history.
    A raw-model redo failure remains atomic, while a later real edit clears redo.
    */
    #[test]
    fn range_history_handles_growth_dirty_state_and_raw_redo_rejection() {
        /*
        First, grow the buffer and verify restored length, cursor, viewport, and dirty state.
        */
        let mut editor = Editor::new(vec![0x90], Mode::Code, 1);
        editor.toggle_edit().unwrap();
        editor.replace_bytes(1, vec![0xc3], (2, 1)).unwrap();
        assert_eq!(editor.data, [0x90, 0xc3]);
        assert_eq!((editor.offset, editor.top, editor.dirty), (2, 1, true));

        assert!(editor.undo().unwrap());
        assert_eq!(editor.data, [0x90]);
        assert_eq!((editor.offset, editor.top, editor.dirty), (1, 0, false));
        /*
        Next, make the pending redo invalid under a raw address model.
        The failure keeps the complete current editor and redo state.
        */
        editor
            .set_raw_model(Some(RawModel {
                base: u64::from(u32::MAX),
                architecture: crate::format::Architecture::X86(32),
                byte_order: ByteOrder::Little,
            }))
            .unwrap();
        let state = (editor.data.clone(), editor.offset, editor.top, editor.dirty);
        assert!(editor.redo().is_err());
        assert_eq!(
            (editor.data.clone(), editor.offset, editor.top, editor.dirty),
            state
        );
        /*
        Finally, restore normal configuration, apply redo, and verify new-edit invalidation.
        Returning bytes to the baseline also clears dirty state.
        */
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

    /*
    This test separates interrupted Hex groups and retains only the newest 256 records.
    Cancellation restores original bytes and clears the retained history.
    */
    #[test]
    fn edit_history_interrupts_hex_groups_and_evicts_oldest_records() {
        /*
        First, a separate replacement interrupts an incomplete nibble group.
        Two undo actions then restore the grouped and original byte states.
        */
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

        /*
        Next, create 257 operations and verify that only the newest 256 remain.
        Cancellation then restores the original baseline and removes all history.
        */
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

    /*
    This test applies the buffered 130 MiB history budget through eviction and refusal.
    An oversized operation preserves bytes, cursor state, dirty state, and the redo branch.
    */
    #[test]
    fn history_byte_limit_evicts_and_rejects_edits_atomically() {
        /*
        First, equal-size large records force byte-based eviction below the 256-record limit.
        Undo reaches the oldest retained byte state and cannot reach the original state.
        */
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

        /*
        Next, an individually oversized record fails while one redo record exists.
        The failure preserves bytes, cursor state, dirty state, and both history branches.
        */
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

    /*
    This test separates source identity from one editor's byte revision.
    State-only actions, no-ops, failures, and saved preserve the current stamp.
    */
    #[test]
    fn source_stamp_ignores_state_only_and_failed_actions() {
        let mut editor = Editor::new(vec![0x12], Mode::Hex, 0);
        let initial = editor.buffer_stamp();
        let other = Editor::new(vec![0x12], Mode::Hex, 0).buffer_stamp();
        assert_ne!(initial, other);

        editor.toggle_edit().unwrap();
        assert_eq!(editor.buffer_stamp(), initial);
        editor.replace_bytes(0, vec![0x12], (0, 0)).unwrap();
        assert_eq!(editor.buffer_stamp(), initial);
        assert!(editor.replace_bytes(2, vec![0], (0, 0)).is_err());
        assert_eq!(editor.buffer_stamp(), initial);
        assert!(!editor.undo().unwrap());
        assert!(!editor.redo().unwrap());
        editor.goto(1, 4);
        assert_eq!(editor.buffer_stamp(), initial);
        editor.cancel_edit();
        assert_eq!(editor.buffer_stamp(), initial);
        editor.saved();
        assert_eq!(editor.buffer_stamp(), initial);

        /*
        Hex no-ops can move nibble state and can close a changed byte group.
        Neither form changes the current bytes, so both preserve the source revision.
        */
        let mut nibble_noop = Editor::new(vec![0x12], Mode::Hex, 0);
        nibble_noop.toggle_edit().unwrap();
        let before_nibbles = nibble_noop.buffer_stamp();
        nibble_noop.hex_digit('1').unwrap();
        nibble_noop.hex_digit('2').unwrap();
        assert_eq!(nibble_noop.buffer_stamp(), before_nibbles);

        let mut grouped_noop = Editor::new(vec![0x12], Mode::Hex, 0);
        grouped_noop.toggle_edit().unwrap();
        grouped_noop.hex_digit('f').unwrap();
        let after_changed_high = grouped_noop.buffer_stamp();
        grouped_noop.hex_digit('2').unwrap();
        assert_eq!(grouped_noop.buffer_stamp(), after_changed_high);
    }

    /*
    This test covers both Hex nibble paths and shared transaction application.
    Undo, Redo, growth, and changed cancellation each create a distinct byte revision.
    */
    #[test]
    fn source_stamp_advances_for_each_actual_byte_mutation() {
        let mut editor = Editor::new(vec![0x12], Mode::Hex, 0);
        editor.toggle_edit().unwrap();

        let before_high = editor.buffer_stamp();
        editor.hex_digit('f').unwrap();
        let after_high = editor.buffer_stamp();
        assert_ne!(after_high, before_high);

        editor.hex_digit('3').unwrap();
        let after_low = editor.buffer_stamp();
        assert_ne!(after_low, after_high);
        assert_eq!(editor.data, [0xf3]);

        assert!(editor.undo().unwrap());
        let after_undo = editor.buffer_stamp();
        assert_ne!(after_undo, after_low);
        assert_eq!(editor.data, [0x12]);

        assert!(editor.redo().unwrap());
        let after_redo = editor.buffer_stamp();
        assert_ne!(after_redo, after_undo);
        assert_eq!(editor.data, [0xf3]);

        editor.replace_bytes(1, vec![0x44], (2, 0)).unwrap();
        let after_growth = editor.buffer_stamp();
        assert_ne!(after_growth, after_redo);
        assert_eq!(editor.data, [0xf3, 0x44]);

        editor.cancel_edit();
        assert_ne!(editor.buffer_stamp(), after_growth);
        assert_eq!(editor.data, [0x12]);
    }

    /*
    This test models successful Save As source adoption and an unchanged cancellation.
    Adoption renews identity before saved, while saved and byte-identical cancellation preserve that stamp.
    */
    #[test]
    fn source_adoption_renews_identity_without_a_saved_revision() {
        let mut editor = Editor::new(vec![0x12], Mode::Hex, 0);
        let initial = editor.buffer_stamp();
        editor.source_changed();
        let adopted = editor.buffer_stamp();
        assert_ne!(adopted, initial);
        editor.saved();
        assert_eq!(editor.buffer_stamp(), adopted);

        editor.toggle_edit().unwrap();
        editor.hex_digit('f').unwrap();
        assert!(editor.undo().unwrap());
        let restored = editor.buffer_stamp();
        assert_eq!(editor.data, [0x12]);
        editor.cancel_edit();
        assert_eq!(editor.buffer_stamp(), restored);
    }
}
