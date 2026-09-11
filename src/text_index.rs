/*
This component maps source-byte offsets to bounded Text row starts.
It keeps sparse checkpoints and one fixed read buffer without storing file contents or one entry per row.
L05.2 adds resumable cancellation and suffix invalidation before L16 connects Text viewing and editing.

Each callback must fill its complete supplied slice or return an I/O error.
The component cannot detect a callback that returns success without filling the slice.
Callbacks must supply stable bytes throughout one query and each resumed scan sequence.
The caller must reset the index after an untracked same-length source change.
*/
use crate::analysis::Outcome;
use std::borrow::Cow;
use std::collections::VecDeque;
use std::io;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

/*
These limits match the Windows Text index contract.
Reads use 64 KiB, Unicode rows use at most 64 KiB, and one grapheme fragment uses at most 4 KiB.
Sparse checkpoints start one MiB apart and never exceed 1,048,576 entries.
*/
const READ_BYTES: usize = 64 * 1024;
const READ_BODY_BYTES: u64 = READ_BYTES as u64 - 1;
const MAX_TEXT_ROW_BYTES: usize = READ_BYTES;
const MAX_GRAPHEME_BYTES: usize = 4 * 1024;
const INITIAL_STRIDE: u64 = 1024 * 1024;
const MAX_CHECKPOINTS: usize = 1024 * 1024;

/*
The codec identifies the source units that produce Text row widths and encoded delimiters.
L16 will connect explicit codec selection and persistence to the application.
*/
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum TextCodec {
    #[default]
    Cp437,
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl TextCodec {
    /*
    Delimiter encoding uses the selected source codec without changing source-byte offsets.
    CP437 delimiters are ASCII bytes, while Unicode codecs use their standard code units.
    */
    fn encode(self, text: &str) -> Vec<u8> {
        match self {
            /* CP437 delimiters use their single-byte ASCII values. */
            Self::Cp437 => text.bytes().collect(),
            /* UTF-8 keeps the delimiter scalar bytes in their normal sequence. */
            Self::Utf8 => text.as_bytes().to_vec(),
            /* UTF-16 writes each delimiter code unit in the selected byte order. */
            Self::Utf16Le => text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            Self::Utf16Be => text.encode_utf16().flat_map(u16::to_be_bytes).collect(),
        }
    }
}

/*
One layout records the values that can change Text row boundaries.
The constructor validates width and delimiter once before any source scan starts.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TextLayout {
    width: usize,
    tabs: bool,
    codec: TextCodec,
    delimiter: [u8; 4],
    delimiter_len: usize,
}

impl TextLayout {
    /*
    The public constructor accepts CR, LF, or CRLF and encodes that delimiter for the selected codec.
    A zero display width cannot make forward row progress and receives an input error.
    */
    pub(crate) fn new(
        width: usize,
        tabs: bool,
        delimiter: &[u8],
        codec: TextCodec,
    ) -> Result<Self, String> {
        if width == 0 {
            return Err("The Text width must be nonzero.".into());
        }
        let text = match delimiter {
            b"\r" => "\r",
            b"\n" => "\n",
            b"\r\n" => "\r\n",
            _ => return Err("The Text delimiter must be CR, LF, or CRLF.".into()),
        };
        let encoded = codec.encode(text);
        let mut stored = [0_u8; 4];
        stored[..encoded.len()].copy_from_slice(&encoded);
        Ok(Self {
            width,
            tabs,
            codec,
            delimiter: stored,
            delimiter_len: encoded.len(),
        })
    }

    /*
    This slice exposes only initialized delimiter bytes to row scanners.
    The selected codec determines whether the slice contains one through four bytes.
    */
    fn delimiter(&self) -> &[u8] {
        &self.delimiter[..self.delimiter_len]
    }

    /*
    CP437 permits configured rows wider than 64 KiB, so its local replay distance follows the width.
    Unicode rows use the fixed byte limit regardless of their displayed width.
    */
    fn max_row_bytes(self) -> u64 {
        if self.codec == TextCodec::Cp437 {
            u64::try_from(self.width)
                .unwrap_or(u64::MAX)
                .saturating_add(self.delimiter_len as u64)
        } else {
            MAX_TEXT_ROW_BYTES as u64
        }
    }
}

/*
This state describes one completed indexed prefix and its current row.
Chunk processing updates the fields only after an exact callback read succeeds.
*/
#[derive(Clone, Copy, Default)]
struct ScanState {
    pos: u64,
    row_start: u64,
    column: usize,
}

/*
The index retains selected row starts, one scan position, one source length, and one reusable read buffer.
Layout or unexplained length changes reset all positions because old checkpoints cannot describe the new source contract.
Explicit suffix invalidation adopts an edited length and preserves only the known valid prefix.
*/
pub(crate) struct TextIndex {
    layout: Option<TextLayout>,
    source_len: Option<u64>,
    checkpoints: Vec<u64>,
    initial_stride: u64,
    stride: u64,
    next_checkpoint: u64,
    progress: ScanState,
    buffer: Box<[u8]>,
    max_checkpoints: usize,
}

/* The default constructor applies the production stride, checkpoint limit, and fixed read buffer. */
impl Default for TextIndex {
    fn default() -> Self {
        Self::with_limits(INITIAL_STRIDE, MAX_CHECKPOINTS)
    }
}

impl TextIndex {
    /*
    Test limits use the same allocation and compaction path as production limits.
    The clamps keep checkpoint spacing nonzero and retain the required initial zero checkpoint.
    */
    fn with_limits(stride: u64, max_checkpoints: usize) -> Self {
        Self {
            layout: None,
            source_len: None,
            checkpoints: vec![0],
            initial_stride: stride.max(1),
            stride: stride.max(1),
            next_checkpoint: stride.max(1),
            progress: ScanState::default(),
            buffer: vec![0; READ_BYTES].into_boxed_slice(),
            max_checkpoints: max_checkpoints.max(2),
        }
    }

    /*
    Reset removes every checkpoint that can describe an earlier source, layout, or incomplete read.
    The fixed read buffer remains allocated for the next query.
    */
    pub(crate) fn reset(&mut self) {
        self.layout = None;
        self.source_len = None;
        self.checkpoints.clear();
        self.checkpoints.push(0);
        self.stride = self.initial_stride;
        self.next_checkpoint = self.initial_stride;
        self.progress = ScanState::default();
    }

    /*
    An edit can complete a delimiter or join a preceding grapheme before its first changed byte.
    Bound the supplied offset by both lengths before applying the codec lookbehind.
    Retain a fully scanned earlier prefix, or restart at the final strictly earlier checkpoint.
    */
    pub(crate) fn invalidate_from(&mut self, change_start: u64, new_len: u64) {
        let old_len = self.source_len.unwrap_or(new_len);
        let bounded_start = change_start.min(old_len).min(new_len);
        let lookbehind = self.layout.map_or(1, |layout| {
            if layout.codec == TextCodec::Cp437 {
                1
            } else {
                MAX_GRAPHEME_BYTES as u64
            }
        });
        let before = bounded_start.saturating_sub(lookbehind);
        self.source_len = Some(new_len);
        if self.layout.is_none() || self.progress.pos < before {
            return;
        }

        /*
        Keep checkpoint zero even when the edit affects the first source byte.
        Preserve the compacted stride so a rebuilt suffix cannot increase retained index density.
        */
        let keep = self
            .checkpoints
            .partition_point(|offset| *offset < before)
            .max(1);
        self.checkpoints.truncate(keep);
        let start = *self.checkpoints.last().unwrap();
        self.progress = ScanState {
            pos: start,
            row_start: start,
            column: 0,
        };
        self.next_checkpoint = start
            .checked_div(self.stride)
            .and_then(|part| part.checked_add(1))
            .and_then(|part| part.checked_mul(self.stride))
            .unwrap_or(u64::MAX);
    }

    /*
    Each query supplies the stable source length and complete layout contract.
    A changed value resets the index before the query can use an old position.
    */
    fn set_source(&mut self, layout: TextLayout, len: u64) {
        if self.layout == Some(layout) && self.source_len == Some(len) {
            return;
        }
        self.reset();
        self.layout = Some(layout);
        self.source_len = Some(len);
    }

    /*
    This reservation estimates the most checkpoints that one forward scan can add.
    Fallible exact reservation keeps vector capacity within the configured checkpoint limit.
    */
    fn reserve_scan(&mut self, stop: u64) -> io::Result<()> {
        let possible = stop
            .saturating_sub(self.progress.pos)
            .div_ceil(self.stride)
            .saturating_add(2);
        let available = self.max_checkpoints.saturating_sub(self.checkpoints.len());
        let count = usize::try_from(possible.min(available as u64)).unwrap_or(available);
        self.checkpoints
            .try_reserve_exact(count)
            .map_err(|_| io::Error::other("Cannot allocate the sparse Text index."))
    }

    /*
    Forward indexing advances the persistent prefix through exact callback reads.
    Poll cancellation before each bounded read and keep every completed scan chunk for a resumed query.
    CP437 keeps delimiter lookahead inside each 64 KiB read, while Unicode uses bounded row decoding.
    */
    fn ensure_to<R, C>(
        &mut self,
        layout: TextLayout,
        len: u64,
        stop: u64,
        read: &mut R,
        cancel: &mut C,
    ) -> io::Result<bool>
    where
        R: FnMut(u64, &mut [u8]) -> io::Result<()>,
        C: FnMut() -> io::Result<bool>,
    {
        let stop = stop.min(len);
        self.reserve_scan(stop)?;
        if layout.codec != TextCodec::Cp437 {
            let mut state = self.progress;
            let complete = scan_unicode_rows(
                &mut state,
                &mut self.buffer,
                layout,
                len,
                stop,
                read,
                cancel,
                |first| {
                    record_sparse_run(
                        &mut self.checkpoints,
                        &mut self.stride,
                        &mut self.next_checkpoint,
                        self.max_checkpoints,
                        first,
                        1,
                        1,
                    );
                },
            )?;
            self.progress = state;
            return Ok(complete);
        }

        /*
        CP437 scans plain byte runs arithmetically and keeps delimiter lookahead across chunk boundaries.
        State changes occur only after the callback fills the complete requested slice.
        */
        while self.progress.pos < stop {
            if cancel()? {
                return Ok(false);
            }
            let read_start = self.progress.pos;
            let process_end = read_start.saturating_add(READ_BODY_BYTES).min(stop);
            let read_end = process_end
                .saturating_add(layout.delimiter_len.saturating_sub(1) as u64)
                .min(len);
            let read_len = usize::try_from(read_end - read_start).unwrap();
            read(read_start, &mut self.buffer[..read_len])?;
            let mut state = self.progress;
            process_chunk(
                &mut state,
                &self.buffer[..read_len],
                read_start,
                process_end,
                len,
                layout,
                |first, step, count| {
                    record_sparse_run(
                        &mut self.checkpoints,
                        &mut self.stride,
                        &mut self.next_checkpoint,
                        self.max_checkpoints,
                        first,
                        step,
                        count,
                    );
                },
            );
            self.progress = state;
        }
        Ok(true)
    }

    /*
    Local replay starts at one known row and emits later row starts through the same processors.
    Cancellation hides a partial answer and never changes the persistent scan position or checkpoints.
    */
    fn scan_from<R, C, E>(
        &mut self,
        layout: TextLayout,
        len: u64,
        range: std::ops::Range<u64>,
        read: &mut R,
        cancel: &mut C,
        mut emit: E,
    ) -> io::Result<bool>
    where
        R: FnMut(u64, &mut [u8]) -> io::Result<()>,
        C: FnMut() -> io::Result<bool>,
        E: FnMut(u64, u64, u64),
    {
        let mut state = ScanState {
            pos: range.start,
            row_start: range.start,
            column: 0,
        };
        let stop = range.end.min(len);
        if layout.codec != TextCodec::Cp437 {
            return scan_unicode_rows(
                &mut state,
                &mut self.buffer,
                layout,
                len,
                stop,
                read,
                cancel,
                |first| emit(first, 1, 1),
            );
        }

        /*
        CP437 local replay uses bounded reads even when a configured row is wider than one buffer.
        The retained column joins consecutive chunks until a delimiter or width boundary ends the row.
        */
        while state.pos < stop {
            if cancel()? {
                return Ok(false);
            }
            let read_start = state.pos;
            let process_end = read_start.saturating_add(READ_BODY_BYTES).min(stop);
            let read_end = process_end
                .saturating_add(layout.delimiter_len.saturating_sub(1) as u64)
                .min(len);
            let read_len = usize::try_from(read_end - read_start).unwrap();
            read(read_start, &mut self.buffer[..read_len])?;
            process_chunk(
                &mut state,
                &self.buffer[..read_len],
                read_start,
                process_end,
                len,
                layout,
                &mut emit,
            );
        }
        Ok(true)
    }

    /*
    Row lookup extends the sparse prefix to the selected byte and replays from its nearest earlier checkpoint.
    Cancellation returns no offset and retains completed persistent chunks for the next query.
    Any callback or allocation error clears the complete index before the error returns.
    */
    pub(crate) fn row_at<R, C>(
        &mut self,
        layout: TextLayout,
        len: u64,
        offset: u64,
        mut read: R,
        mut cancel: C,
    ) -> io::Result<Outcome<u64>>
    where
        R: FnMut(u64, &mut [u8]) -> io::Result<()>,
        C: FnMut() -> io::Result<bool>,
    {
        self.set_source(layout, len);
        let result = self.row_at_inner(layout, len, offset, &mut read, &mut cancel);
        if result.is_err() {
            self.reset();
        }
        result
    }

    /*
    This inner operation contains the normal row lookup without the shared error-reset wrapper.
    The target clamps to the final source byte, and an empty source returns offset zero.
    */
    fn row_at_inner<R, C>(
        &mut self,
        layout: TextLayout,
        len: u64,
        offset: u64,
        read: &mut R,
        cancel: &mut C,
    ) -> io::Result<Outcome<u64>>
    where
        R: FnMut(u64, &mut [u8]) -> io::Result<()>,
        C: FnMut() -> io::Result<bool>,
    {
        if len == 0 {
            return Ok(Outcome::Completed(0));
        }
        let target = offset.min(len - 1);
        if !self.ensure_to(layout, len, target + 1, read, cancel)? {
            return Ok(Outcome::Canceled);
        }
        let start = self.checkpoint(target);
        let mut answer = start;
        if !self.scan_from(
            layout,
            len,
            start..target + 1,
            read,
            cancel,
            |first, step, count| {
                if first <= target {
                    let index = ((target - first) / step).min(count - 1);
                    answer = first + index * step;
                }
            },
        )? {
            return Ok(Outcome::Canceled);
        }
        Ok(Outcome::Completed(answer))
    }

    /*
    Previous retains at most the requested row count plus one recent position.
    Cancellation returns no offset and retains completed persistent chunks for the next query.
    Fallible allocation occurs before replay, and an error resets the complete index.
    */
    pub(crate) fn previous<R, C>(
        &mut self,
        layout: TextLayout,
        len: u64,
        top: u64,
        rows: usize,
        mut read: R,
        mut cancel: C,
    ) -> io::Result<Outcome<u64>>
    where
        R: FnMut(u64, &mut [u8]) -> io::Result<()>,
        C: FnMut() -> io::Result<bool>,
    {
        self.set_source(layout, len);
        let result = self.previous_inner(layout, len, top, rows, &mut read, &mut cancel);
        if result.is_err() {
            self.reset();
        }
        result
    }

    /*
    This inner operation builds the needed prefix and replays only a bounded earlier distance.
    The recent queue discards older positions as later row starts approach the selected row.
    */
    fn previous_inner<R, C>(
        &mut self,
        layout: TextLayout,
        len: u64,
        top: u64,
        rows: usize,
        read: &mut R,
        cancel: &mut C,
    ) -> io::Result<Outcome<u64>>
    where
        R: FnMut(u64, &mut [u8]) -> io::Result<()>,
        C: FnMut() -> io::Result<bool>,
    {
        if len == 0 {
            return Ok(Outcome::Completed(0));
        }
        let target = top.min(len - 1);
        if !self.ensure_to(layout, len, target + 1, read, cancel)? {
            return Ok(Outcome::Canceled);
        }
        let row_count = u64::try_from(rows).unwrap_or(u64::MAX);
        let distance = row_count.saturating_mul(layout.max_row_bytes());
        let start = self.checkpoint(target.saturating_sub(distance));
        let keep = rows.saturating_add(1).max(1);
        let mut recent = VecDeque::new();
        recent
            .try_reserve_exact(keep)
            .map_err(|_| io::Error::other("Cannot allocate previous Text row positions."))?;
        recent.push_back(start);
        if !self.scan_from(
            layout,
            len,
            start..target + 1,
            read,
            cancel,
            |first, step, count| {
                append_recent(&mut recent, keep, target, first, step, count);
            },
        )? {
            return Ok(Outcome::Canceled);
        }
        Ok(Outcome::Completed(recent.front().copied().unwrap_or(0)))
    }

    /*
    Last extends the complete index and returns the reference row-start convention.
    Cancellation retains completed persistent chunks and returns no partial final row.
    CP437 keeps the last nonempty row start, while Unicode records the next position, including EOF.
    */
    pub(crate) fn last<R, C>(
        &mut self,
        layout: TextLayout,
        len: u64,
        mut read: R,
        mut cancel: C,
    ) -> io::Result<Outcome<u64>>
    where
        R: FnMut(u64, &mut [u8]) -> io::Result<()>,
        C: FnMut() -> io::Result<bool>,
    {
        self.set_source(layout, len);
        let result = self.ensure_to(layout, len, len, &mut read, &mut cancel);
        match result {
            Ok(true) => Ok(Outcome::Completed(self.progress.row_start)),
            Ok(false) => Ok(Outcome::Canceled),
            Err(error) => {
                self.reset();
                Err(error)
            }
        }
    }

    /*
    Next scans from a supplied known row start, so a distant source offset needs only local bounded reads.
    The noncancellable operation can extend a nearby prefix before its bounded local successor lookup.
    The caller must reset after untracked same-length source changes.
    */
    pub(crate) fn next<R>(
        &mut self,
        layout: TextLayout,
        len: u64,
        start: u64,
        mut read: R,
    ) -> io::Result<u64>
    where
        R: FnMut(u64, &mut [u8]) -> io::Result<()>,
    {
        self.set_source(layout, len);
        let result = self.next_inner(layout, len, start, &mut read);
        if result.is_err() {
            self.reset();
        }
        result
    }

    /*
    This inner operation uses the maximum row-byte contract as its local stop.
    It extends nearby progress when useful and otherwise leaves the persistent prefix unchanged.
    */
    fn next_inner<R>(
        &mut self,
        layout: TextLayout,
        len: u64,
        start: u64,
        read: &mut R,
    ) -> io::Result<u64>
    where
        R: FnMut(u64, &mut [u8]) -> io::Result<()>,
    {
        if len == 0 || start >= len {
            return Ok(len);
        }
        let mut never_cancel = || Ok(false);
        let stop = start
            .saturating_add(layout.max_row_bytes())
            .saturating_add(1)
            .min(len);
        if self.progress.pos <= start
            && start.saturating_sub(self.progress.pos) <= layout.max_row_bytes()
        {
            let complete = self.ensure_to(layout, len, stop, read, &mut never_cancel)?;
            debug_assert!(complete);
        }
        let mut answer = len;
        let complete = self.scan_from(
            layout,
            len,
            start..stop,
            read,
            &mut never_cancel,
            |first, _, _| {
                if answer == len {
                    answer = first;
                }
            },
        )?;
        debug_assert!(complete);
        Ok(answer)
    }

    /*
    Binary search selects the final retained checkpoint at or before one target.
    Checkpoint zero always exists, so subtraction cannot produce an invalid index.
    */
    fn checkpoint(&self, target: u64) -> u64 {
        let index = self
            .checkpoints
            .partition_point(|checkpoint| *checkpoint <= target)
            .saturating_sub(1);
        self.checkpoints[index]
    }
}

/*
These decode records map valid or replacement scalars back to their exact source-byte ranges.
Segments then split extended graphemes only at scalar-safe 4 KiB boundaries.
*/
#[derive(Clone, Copy)]
struct Unit {
    source_start: usize,
    source_end: usize,
    text_start: usize,
    text_end: usize,
}

#[derive(Clone, Copy)]
struct Segment {
    source_start: usize,
    source_end: usize,
    text_start: usize,
    text_end: usize,
    fallback: bool,
}

enum Decoded {
    Scalar(char, usize),
    Incomplete,
}

/*
This helper reads one complete UTF-16 code unit in selected byte order.
An incomplete slice returns no unit and lets the scalar decoder select window-tail or file-tail behavior.
*/
fn read_u16(data: &[u8], offset: usize, little: bool) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(if little {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

/*
Strict decoding advances invalid UTF-8 by one byte and invalid UTF-16 by one code unit.
Incomplete window tails wait for another read, while incomplete file tails become replacement scalars.
*/
fn decode_scalar(data: &[u8], offset: usize, codec: TextCodec, at_eof: bool) -> Decoded {
    match codec {
        /* Each CP437 byte occupies one source position and needs no multibyte validation. */
        TextCodec::Cp437 => Decoded::Scalar(char::from(data[offset]), 1),
        TextCodec::Utf8 => {
            /* The lead byte selects a candidate length before strict UTF-8 validates the complete scalar. */
            let first = data[offset];
            let len = match first {
                0x00..=0x7f => 1,
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return Decoded::Scalar('\u{fffd}', 1),
            };
            let Some(bytes) = data.get(offset..offset.saturating_add(len)) else {
                return if at_eof {
                    Decoded::Scalar('\u{fffd}', 1)
                } else {
                    Decoded::Incomplete
                };
            };
            match std::str::from_utf8(bytes)
                .ok()
                .and_then(|text| text.chars().next())
            {
                Some(character) => Decoded::Scalar(character, len),
                None => Decoded::Scalar('\u{fffd}', 1),
            }
        }
        TextCodec::Utf16Le | TextCodec::Utf16Be => {
            /* The first ordered code unit selects a basic scalar, invalid unit, or surrogate pair. */
            let little = codec == TextCodec::Utf16Le;
            let Some(high) = read_u16(data, offset, little) else {
                return if at_eof {
                    Decoded::Scalar('\u{fffd}', 1)
                } else {
                    Decoded::Incomplete
                };
            };
            if (0xd800..=0xdbff).contains(&high) {
                /* A high surrogate needs one following low surrogate before the decoder can publish a scalar. */
                let Some(low) = read_u16(data, offset + 2, little) else {
                    return if at_eof {
                        Decoded::Scalar('\u{fffd}', 2)
                    } else {
                        Decoded::Incomplete
                    };
                };
                if !(0xdc00..=0xdfff).contains(&low) {
                    return Decoded::Scalar('\u{fffd}', 2);
                }
                let scalar =
                    0x1_0000 + ((u32::from(high) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
                Decoded::Scalar(char::from_u32(scalar).unwrap(), 4)
            } else if (0xdc00..=0xdfff).contains(&high) {
                /* A lone low surrogate becomes one replacement scalar and preserves its two-byte source range. */
                Decoded::Scalar('\u{fffd}', 2)
            } else {
                /* Every nonsurrogate code unit maps directly to one Unicode scalar. */
                Decoded::Scalar(char::from_u32(u32::from(high)).unwrap(), 2)
            }
        }
    }
}

/*
This decoder builds one bounded Unicode string and its exact source mapping.
Extended graphemes split into scalar-safe fragments when one source cluster exceeds 4 KiB.
*/
fn decoded_segments(data: &[u8], codec: TextCodec, at_eof: bool) -> (String, Vec<Segment>) {
    /*
    Decode complete source units into one bounded string and retain every byte-to-text range.
    An incomplete window tail stays outside the mapping for the next source read.
    */
    let mut text = String::with_capacity(data.len());
    let mut units = Vec::new();
    let mut source = 0;
    while source < data.len() {
        let Decoded::Scalar(character, len) = decode_scalar(data, source, codec, at_eof) else {
            break;
        };
        let text_start = text.len();
        text.push(character);
        units.push(Unit {
            source_start: source,
            source_end: source + len,
            text_start,
            text_end: text.len(),
        });
        source += len;
    }

    /*
    Each grapheme becomes one or more source-mapped segments.
    Later fragments and zero-width clusters request a dotted-circle width fallback.
    */
    let mut segments = Vec::new();
    let mut first_unit = 0;
    for (text_start, cluster) in text.grapheme_indices(true) {
        let text_end = text_start + cluster.len();
        let mut end_unit = first_unit;
        while end_unit < units.len() && units[end_unit].text_start < text_end {
            end_unit += 1;
        }
        let mut part = first_unit;
        while part < end_unit {
            let limit = units[part].source_start.saturating_add(MAX_GRAPHEME_BYTES);
            let mut part_end = part + 1;
            while part_end < end_unit && units[part_end].source_end <= limit {
                part_end += 1;
            }
            let part_text = &text[units[part].text_start..units[part_end - 1].text_end];
            segments.push(Segment {
                source_start: units[part].source_start,
                source_end: units[part_end - 1].source_end,
                text_start: units[part].text_start,
                text_end: units[part_end - 1].text_end,
                fallback: part != first_unit || UnicodeWidthStr::width(part_text) == 0,
            });
            part = part_end;
        }
        first_unit = end_unit;
    }
    (text, segments)
}

/*
The width helper replaces control scalars before it measures extended grapheme clusters.
This local copy matches the Windows console boundary without changing Linux terminal rendering.
*/
fn visible_text_width(text: &str) -> usize {
    let visible = if text.chars().any(char::is_control) {
        Cow::Owned(
            text.chars()
                .map(|character| {
                    if character.is_control() {
                        '\u{fffd}'
                    } else {
                        character
                    }
                })
                .collect::<String>(),
        )
    } else {
        Cow::Borrowed(text)
    };
    visible
        .graphemes(true)
        .map(|cluster| UnicodeWidthStr::width(cluster).max(usize::from(!cluster.is_empty())))
        .sum()
}

/*
One row walk returns the next source byte and whether the boundary is stable in the current window.
An incomplete final grapheme waits unless EOF or the 64 KiB row limit makes the boundary final.
*/
#[derive(Clone, Copy)]
struct RowWalk {
    next: usize,
    complete: bool,
}

/*
Unicode row walking recognizes encoded delimiters before it applies display wrapping.
A first wide grapheme can exceed width one, but the following segment starts a new row without tab underflow.
*/
fn walk_decoded_row(
    data: &[u8],
    text: &str,
    segments: &[Segment],
    start: usize,
    layout: TextLayout,
    at_eof: bool,
) -> RowWalk {
    let hard_end = data.len().saturating_sub(start) >= MAX_TEXT_ROW_BYTES;
    let stable_segments = if at_eof || hard_end {
        segments.len()
    } else {
        segments.len().saturating_sub(1)
    };
    let mut pos = start;
    let mut column = 0;
    let first = segments[..stable_segments].partition_point(|segment| segment.source_end <= start);
    for segment in &segments[first..stable_segments] {
        if segment.source_start.saturating_sub(start) >= MAX_TEXT_ROW_BYTES {
            return RowWalk {
                next: segment.source_start,
                complete: true,
            };
        }
        if data[segment.source_start..].starts_with(layout.delimiter()) {
            return RowWalk {
                next: segment.source_start + layout.delimiter_len,
                complete: true,
            };
        }
        if column >= layout.width {
            return RowWalk {
                next: segment.source_start,
                complete: true,
            };
        }

        /*
        Tabs expand to the next eight-column boundary within the remaining row width.
        Grapheme fragments use their visible cluster width or the dotted-circle fallback width.
        */
        let cluster = &text[segment.text_start..segment.text_end];
        let span = if cluster == "\t" && layout.tabs {
            (8 - column % 8).min(layout.width.saturating_sub(column))
        } else if segment.fallback {
            let mut display = String::with_capacity('◌'.len_utf8() + cluster.len());
            display.push('◌');
            display.push_str(cluster);
            visible_text_width(&display)
        } else {
            visible_text_width(cluster)
        };
        if column > 0 && column.saturating_add(span) > layout.width {
            return RowWalk {
                next: segment.source_start,
                complete: true,
            };
        }
        pos = segment.source_end;
        column = column.saturating_add(span);
    }
    RowWalk {
        next: pos,
        complete: at_eof || hard_end,
    }
}

/*
Unicode scanning decodes each 64 KiB source window once and walks complete rows inside that mapping.
Every emitted value is an exact source-byte offset below EOF.
Cancellation occurs before each read and preserves all state from earlier complete windows.
The scan state can retain EOF as the reference Unicode last-row result.
*/
#[allow(clippy::too_many_arguments)]
fn scan_unicode_rows<R, C, E>(
    state: &mut ScanState,
    buffer: &mut [u8],
    layout: TextLayout,
    len: u64,
    stop: u64,
    read: &mut R,
    cancel: &mut C,
    mut emit: E,
) -> io::Result<bool>
where
    R: FnMut(u64, &mut [u8]) -> io::Result<()>,
    C: FnMut() -> io::Result<bool>,
    E: FnMut(u64),
{
    while state.pos < stop && state.pos < len {
        if cancel()? {
            return Ok(false);
        }
        /* Read one bounded source window before the decoder identifies complete scalar and grapheme ranges. */
        let read_start = state.pos;
        let read_len = usize::try_from((len - read_start).min(READ_BYTES as u64)).unwrap();
        read(read_start, &mut buffer[..read_len])?;
        let at_eof = read_start + read_len as u64 == len;
        let (text, segments) = decoded_segments(&buffer[..read_len], layout.codec, at_eof);

        /*
        Walk all complete rows in the decoded mapping.
        Retain an unfinished final grapheme for the next window unless the row reaches its byte cap.
        */
        let mut local = 0;
        while local < read_len && state.pos < stop {
            let walk =
                walk_decoded_row(&buffer[..read_len], &text, &segments, local, layout, at_eof);
            if !walk.complete {
                break;
            }
            if walk.next == 0 || walk.next <= local {
                return Err(io::Error::other("Unicode Text indexing made no progress."));
            }
            local = walk.next;
            state.pos = read_start + local as u64;
            state.row_start = state.pos;
            state.column = 0;
            if state.pos < len {
                emit(state.pos);
            }
        }
        if state.pos == read_start {
            return Err(io::Error::other("Unicode Text indexing made no progress."));
        }
    }
    Ok(true)
}

/*
The recent-row queue keeps only positions needed by one upward request.
Arithmetic runs avoid visiting each wrapped CP437 row when a plain byte range spans many rows.
*/
fn append_recent(
    recent: &mut VecDeque<u64>,
    keep: usize,
    target: u64,
    first: u64,
    step: u64,
    count: u64,
) {
    if first > target {
        return;
    }
    let count = count.min((target - first) / step + 1);
    let keep_count = count.min(keep as u64);
    if count >= keep as u64 {
        recent.clear();
    }
    let first_kept = count - keep_count;
    for index in first_kept..count {
        if recent.len() == keep {
            recent.pop_front();
        }
        recent.push_back(first + index * step);
    }
}

/*
This CP437 processor consumes one exact buffer and emits row starts as arithmetic runs.
Delimiter recognition occurs before wrapping, and tabs preserve eight-column expansion within the configured width.
*/
fn process_chunk(
    state: &mut ScanState,
    data: &[u8],
    base: u64,
    process_end: u64,
    len: u64,
    layout: TextLayout,
    mut emit: impl FnMut(u64, u64, u64),
) {
    let delimiter = layout.delimiter();
    while state.pos < process_end {
        let index = usize::try_from(state.pos - base).unwrap();
        if data[index..].starts_with(delimiter) {
            state.pos += delimiter.len() as u64;
            state.column = 0;
            if state.pos < len {
                state.row_start = state.pos;
                emit(state.pos, 1, 1);
            }
            continue;
        }
        if state.column == layout.width {
            state.row_start = state.pos;
            state.column = 0;
            emit(state.pos, 1, 1);
            continue;
        }

        /*
        Plain bytes advance in one arithmetic group until a delimiter lead byte or tab needs individual handling.
        The grouped path records wrap boundaries without storing one offset per row.
        */
        let available = usize::try_from(process_end - state.pos).unwrap();
        let special = data[index..index + available]
            .iter()
            .position(|byte| *byte == delimiter[0] || (layout.tabs && *byte == b'\t'))
            .unwrap_or(available);
        if special > 0 {
            consume_plain(state, special as u64, layout.width as u64, &mut emit);
            continue;
        }
        if layout.tabs && data[index] == b'\t' {
            state.pos += 1;
            let count = (8 - state.column % 8).min(layout.width - state.column);
            state.column += count;
        } else {
            consume_plain(state, 1, layout.width as u64, &mut emit);
        }
    }
}

/*
Plain-byte consumption calculates all complete width boundaries without per-byte work.
The final state retains the last emitted row and its current column for the next buffer.
*/
fn consume_plain(
    state: &mut ScanState,
    count: u64,
    width: u64,
    mut emit: impl FnMut(u64, u64, u64),
) {
    let mut remaining = count;
    let available = width - state.column as u64;
    let take = remaining.min(available);
    state.pos += take;
    state.column += take as usize;
    remaining -= take;
    if remaining == 0 {
        return;
    }
    let first = state.pos;
    let event_count = (remaining - 1) / width + 1;
    emit(first, width, event_count);
    let last_index = event_count - 1;
    state.row_start = first + last_index * width;
    state.pos += remaining;
    state.column = usize::try_from(remaining - last_index * width).unwrap();
}

/*
Checkpoint recording selects row starts at the current stride without storing every row.
When the limit fills, compaction retains alternate entries and doubles the future stride.
*/
fn record_sparse_run(
    checkpoints: &mut Vec<u64>,
    stride: &mut u64,
    next_checkpoint: &mut u64,
    max_checkpoints: usize,
    first: u64,
    step: u64,
    count: u64,
) {
    /*
    Select the first emitted row at each pending stride point.
    Arithmetic skips all other rows in the supplied regular run.
    */
    let last = first.saturating_add(step.saturating_mul(count.saturating_sub(1)));
    while *next_checkpoint <= last {
        let index = if *next_checkpoint <= first {
            0
        } else {
            (*next_checkpoint - first).div_ceil(step)
        };
        if index >= count {
            break;
        }
        let checkpoint = first + index * step;
        if checkpoints.len() == max_checkpoints {
            /*
            Keep alternate checkpoints when the vector reaches its fixed entry limit.
            The doubled stride reduces future density without increasing vector capacity.
            */
            let mut index = 0;
            checkpoints.retain(|_| {
                let keep = index % 2 == 0;
                index += 1;
                keep
            });
            *stride = stride.saturating_mul(2).max(1);
        }
        if checkpoints.last().copied() != Some(checkpoint) {
            checkpoints.push(checkpoint);
        }
        *next_checkpoint = checkpoint
            .checked_div(*stride)
            .and_then(|part| part.checked_add(1))
            .and_then(|part| part.checked_mul(*stride))
            .unwrap_or(u64::MAX);
    }
}

/*
These tests use bounded byte sources and generated high-offset callbacks.
They verify exact row boundaries, sparse state, Unicode decoding, and error recovery before viewer integration.
*/
#[cfg(test)]
mod tests {
    use super::*;
    use crate::paged::{PagedEditCursor, PagedFile};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    /*
    This constructor selects one test layout while keeping every codec and delimiter explicit.
    Individual tests change only the values that affect their boundary.
    */
    fn layout(width: usize, tabs: bool, delimiter: &[u8], codec: TextCodec) -> TextLayout {
        TextLayout::new(width, tabs, delimiter, codec).unwrap()
    }

    /* Existing row tests use a callback that keeps every bounded scan active. */
    fn never_cancel() -> io::Result<bool> {
        Ok(false)
    }

    /*
    This exact-fill adapter records each source offset and rejects any range outside its byte slice.
    Returning success means the callback filled every requested byte, as the production API requires.
    */
    fn reader<'a>(
        data: &'a [u8],
        reads: &'a mut Vec<(u64, usize)>,
    ) -> impl FnMut(u64, &mut [u8]) -> io::Result<()> + 'a {
        move |start, output| {
            reads.push((start, output.len()));
            let start = usize::try_from(start).map_err(|_| io::Error::other("Bad test range."))?;
            let end = start
                .checked_add(output.len())
                .ok_or_else(|| io::Error::other("Bad test range."))?;
            let source = data
                .get(start..end)
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "Short test read."))?;
            output.copy_from_slice(source);
            Ok(())
        }
    }

    /*
    One disposable file owner gives PagedFile adapter tests native regular-file input.
    Drop removes its complete directory after each test.
    */
    struct Fixture(PathBuf);

    impl Fixture {
        /* Create one unique directory so concurrent test processes cannot share a source file. */
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "hview-text-index-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    /* Remove all disposable files when the owning test fixture leaves scope. */
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    /*
    This adapter turns one owned paged read window into the exact-fill callback contract.
    A clipped result becomes UnexpectedEof instead of claiming that missing bytes were filled.
    */
    fn paged_reader<'a>(paged: &'a PagedFile) -> impl FnMut(u64, &mut [u8]) -> io::Result<()> + 'a {
        move |start, output| {
            let window = paged.read_window(start, output.len())?;
            if window.start != start || window.bytes.len() != output.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "The paged source returned a short Text index read.",
                ));
            }
            output.copy_from_slice(&window.bytes);
            Ok(())
        }
    }

    /*
    Empty and single-row files establish exact EOF and last-row conventions.
    CP437 retains its last nonempty row start, while Unicode records the next position through EOF.
    */
    #[test]
    fn empty_single_row_and_eof_results_match_the_reference() {
        let cp437 = layout(80, false, b"\n", TextCodec::Cp437);
        let utf8 = layout(80, false, b"\n", TextCodec::Utf8);
        let mut index = TextIndex::default();
        let mut reads = Vec::new();
        /* CP437 keeps its initial row for empty, single-row, and delimiter-at-EOF sources. */
        assert_eq!(
            index
                .row_at(cp437, 0, 0, reader(b"", &mut reads), never_cancel)
                .unwrap(),
            Outcome::Completed(0)
        );
        assert_eq!(
            index
                .last(cp437, 3, reader(b"abc", &mut reads), never_cancel)
                .unwrap(),
            Outcome::Completed(0)
        );
        assert_eq!(
            index
                .row_at(cp437, 3, 3, reader(b"abc", &mut reads), never_cancel)
                .unwrap(),
            Outcome::Completed(0)
        );
        assert_eq!(
            index.next(cp437, 3, 0, reader(b"abc", &mut reads)).unwrap(),
            3
        );
        assert_eq!(
            index
                .last(cp437, 4, reader(b"abc\n", &mut reads), never_cancel)
                .unwrap(),
            Outcome::Completed(0)
        );
        /* Unicode advances the final scan state through the complete file, including a trailing delimiter. */
        assert_eq!(
            index
                .last(utf8, 3, reader(b"abc", &mut reads), never_cancel)
                .unwrap(),
            Outcome::Completed(3)
        );
        assert_eq!(
            index
                .last(utf8, 2, reader(b"a\n", &mut reads), never_cancel)
                .unwrap(),
            Outcome::Completed(2)
        );
        assert!(index.checkpoints.iter().all(|offset| *offset < 2));
    }

    /*
    These rows cover CR, LF, CRLF, tab expansion, wrapping, and upward movement.
    Delimiters take priority when one delimiter starts at an exact wrap boundary.
    */
    #[test]
    fn byte_delimiters_tabs_and_previous_rows_are_exact() {
        /* Reject layouts that cannot define a supported row progression or delimiter. */
        assert_eq!(
            TextLayout::new(0, false, b"\n", TextCodec::Cp437).unwrap_err(),
            "The Text width must be nonzero."
        );
        assert_eq!(
            TextLayout::new(80, false, b"x", TextCodec::Cp437).unwrap_err(),
            "The Text delimiter must be CR, LF, or CRLF."
        );
        /* Use each delimiter to check lookup, forward movement, and bounded previous-row storage. */
        for delimiter in [b"\r".as_slice(), b"\n".as_slice(), b"\r\n".as_slice()] {
            let mut data = b"abc".to_vec();
            data.extend_from_slice(delimiter);
            data.extend_from_slice(b"defgh");
            let layout = layout(3, false, delimiter, TextCodec::Cp437);
            let mut index = TextIndex::default();
            let mut reads = Vec::new();
            let second = 3 + delimiter.len() as u64;
            assert_eq!(
                index
                    .row_at(
                        layout,
                        data.len() as u64,
                        second,
                        reader(&data, &mut reads),
                        never_cancel,
                    )
                    .unwrap(),
                Outcome::Completed(second)
            );
            assert_eq!(
                index
                    .next(layout, data.len() as u64, 0, reader(&data, &mut reads))
                    .unwrap(),
                second
            );
            assert_eq!(
                index
                    .previous(
                        layout,
                        data.len() as u64,
                        second + 3,
                        2,
                        reader(&data, &mut reads),
                        never_cancel,
                    )
                    .unwrap(),
                Outcome::Completed(0)
            );
        }

        /* Expanded tabs consume the remaining columns through the next eight-column boundary. */
        let data = b"ab\tc\nZ";
        let tabs = layout(9, true, b"\n", TextCodec::Cp437);
        let mut index = TextIndex::default();
        let mut reads = Vec::new();
        assert_eq!(
            index
                .next(tabs, data.len() as u64, 0, reader(data, &mut reads))
                .unwrap(),
            5
        );
    }

    /*
    CRLF crosses the 65,535-byte CP437 processing boundary inside one bounded read.
    A CP437 row wider than 64 KiB continues through more than one exact callback read.
    */
    #[test]
    fn crlf_and_wide_cp437_rows_cross_read_windows() {
        /* Put CRLF across the CP437 processing body while retaining one lookahead byte. */
        let mut data = vec![b'x'; READ_BODY_BYTES as usize - 1];
        data.extend_from_slice(b"\r\nend");
        let second = READ_BODY_BYTES + 1;
        let wide = layout(READ_BYTES + 32, false, b"\r\n", TextCodec::Cp437);
        let mut index = TextIndex::default();
        let mut reads = Vec::new();
        assert_eq!(
            index
                .next(wide, data.len() as u64, 0, reader(&data, &mut reads))
                .unwrap(),
            second
        );
        assert_eq!(
            index
                .row_at(
                    wide,
                    data.len() as u64,
                    second,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(second)
        );
        assert!(reads.iter().all(|(_, count)| *count <= READ_BYTES));

        /* A configured CP437 row can require multiple bounded source reads before EOF. */
        let plain = vec![b'x'; READ_BYTES + 20];
        let mut index = TextIndex::default();
        reads.clear();
        assert_eq!(
            index
                .next(wide, plain.len() as u64, 0, reader(&plain, &mut reads))
                .unwrap(),
            (READ_BYTES + 32).min(plain.len()) as u64
        );
        assert!(reads.len() >= 2);
        assert!(reads.iter().all(|(_, count)| *count <= READ_BYTES));
    }

    /*
    Cold lookup builds sparse checkpoints across a bounded multi-megabyte source.
    Warm lookup replays from a nearby checkpoint, and distant Next reads one local window.
    */
    #[test]
    fn cold_warm_and_distant_queries_have_bounded_read_counts() {
        let data = vec![b'x'; 4 * 1024 * 1024];
        let layout = layout(80, false, b"\n", TextCodec::Cp437);
        let target = data.len() as u64 - 10;
        let mut index = TextIndex::default();
        let mut reads = Vec::new();
        /* The cold query builds checkpoints without storing one entry for each 80-byte row. */
        assert_eq!(
            index
                .row_at(
                    layout,
                    data.len() as u64,
                    target,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(target / 80 * 80)
        );
        let cold = reads.len();
        assert!(cold > 32 && cold < 96, "cold read count: {cold}");
        /* The warm query replays only the preceding checkpoint stride. */
        reads.clear();
        let warm_target = target - 1000;
        assert_eq!(
            index
                .row_at(
                    layout,
                    data.len() as u64,
                    warm_target,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(warm_target / 80 * 80)
        );
        assert!(reads.len() <= 17);

        /* A distant known row start uses one local read without indexing its complete prefix. */
        let start = (3 * 1024 * 1024 / 80 * 80) as u64;
        let mut local = TextIndex::default();
        reads.clear();
        assert_eq!(
            local
                .next(layout, data.len() as u64, start, reader(&data, &mut reads))
                .unwrap(),
            start + 80
        );
        assert_eq!(reads.len(), 1);
    }

    /*
    A small checkpoint limit forces the production compaction path.
    Exact row answers remain stable while length and vector capacity stay within the configured limit.
    */
    #[test]
    fn checkpoint_compaction_keeps_exact_rows_and_bounded_capacity() {
        let data = vec![b'x'; 4096];
        let layout = layout(7, false, b"\n", TextCodec::Cp437);
        let mut index = TextIndex::with_limits(64, 4);
        let mut reads = Vec::new();
        assert_eq!(
            index
                .row_at(
                    layout,
                    data.len() as u64,
                    4000,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(3997)
        );
        assert!(index.checkpoints.len() <= 4);
        assert!(index.checkpoints.capacity() <= 4);
        assert!(index.stride > 64);
        for target in [63, 127, 193, 3001] {
            assert_eq!(
                index
                    .row_at(
                        layout,
                        data.len() as u64,
                        target,
                        reader(&data, &mut reads),
                        never_cancel,
                    )
                    .unwrap(),
                Outcome::Completed(target / 7 * 7)
            );
        }
    }

    /*
    Layout and length changes reset automatically before a query.
    Same-length source edits require the documented explicit reset before new boundaries become authoritative.
    */
    #[test]
    fn layout_length_and_explicit_source_resets_replace_old_state() {
        let mut data = b"abc\ndef".to_vec();
        let narrow = layout(2, false, b"\n", TextCodec::Cp437);
        let wide = layout(80, false, b"\n", TextCodec::Cp437);
        let mut index = TextIndex::default();
        let mut reads = Vec::new();
        /* Layout and length changes replace all old checkpoint state automatically. */
        assert_eq!(
            index
                .row_at(
                    narrow,
                    data.len() as u64,
                    6,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(6)
        );
        assert_eq!(
            index
                .row_at(
                    wide,
                    data.len() as u64,
                    6,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(4)
        );
        assert_eq!(
            index
                .row_at(wide, 3, 2, reader(&data[..3], &mut reads), never_cancel)
                .unwrap(),
            Outcome::Completed(0)
        );
        assert_eq!(
            index
                .row_at(
                    wide,
                    data.len() as u64,
                    6,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(4)
        );
        /* A same-length mutation needs an explicit reset before the index reads new boundaries. */
        data.copy_from_slice(b"abcdefg");
        index.reset();
        assert_eq!(
            index
                .row_at(
                    wide,
                    data.len() as u64,
                    6,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(0)
        );
        let mut fresh = TextIndex::default();
        assert_eq!(
            index
                .row_at(
                    wide,
                    data.len() as u64,
                    6,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            fresh
                .row_at(
                    wide,
                    data.len() as u64,
                    6,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap()
        );
    }

    /*
    Callback errors clear all positions that can describe an incomplete scan.
    The paged adapter also converts a clipped read into the required exact short-read error.
    */
    #[test]
    fn callback_and_paged_short_read_errors_do_not_poison_state() {
        let layout = layout(4, false, b"\n", TextCodec::Utf8);
        let data = vec![b'x'; 1024];
        let mut index = TextIndex::with_limits(64, 8);
        let mut reads = Vec::new();
        assert_eq!(
            index
                .row_at(
                    layout,
                    data.len() as u64,
                    700,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(700)
        );
        assert!(index.progress.pos > 0);
        assert!(index.checkpoints.len() > 1);
        /* Build Unicode progress first, then fail a later exact read and check the complete reset. */
        let error = index
            .row_at(
                layout,
                data.len() as u64,
                900,
                |_, _| Err(io::Error::other("Injected read failure.")),
                never_cancel,
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "Injected read failure.");
        assert_eq!(index.layout, None);
        assert_eq!(index.source_len, None);
        assert_eq!(index.checkpoints, [0]);
        assert_eq!(index.stride, 64);
        assert_eq!(index.next_checkpoint, 64);
        assert_eq!(index.progress.pos, 0);
        assert_eq!(index.progress.row_start, 0);
        assert_eq!(index.progress.column, 0);

        /* A supplied length above the PagedFile length must become an exact short-read error. */
        let fixture = Fixture::new();
        let path = fixture.0.join("paged.bin");
        fs::write(&path, b"abc").unwrap();
        let paged = PagedFile::open(&path).unwrap();
        let error = index
            .row_at(layout, 4, 3, paged_reader(&paged), never_cancel)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(index.layout, None);
        assert_eq!(index.checkpoints, [0]);

        /* An impossible recent-row allocation must fail before it retains any requested offsets. */
        let mut allocation_reads = Vec::new();
        let error = index
            .previous(
                layout,
                4,
                3,
                usize::MAX,
                reader(b"abcd", &mut allocation_reads),
                never_cancel,
            )
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Cannot allocate previous Text row positions."
        );
        assert_eq!(index.layout, None);
        assert_eq!(index.checkpoints, [0]);

        /* A new exact PagedFile source succeeds after each failed query reset. */
        fs::write(&path, b"abcd").unwrap();
        let paged = PagedFile::open(&path).unwrap();
        assert_eq!(
            index
                .row_at(layout, 4, 3, paged_reader(&paged), never_cancel)
                .unwrap(),
            Outcome::Completed(0)
        );
    }

    /*
    UTF-8 and both UTF-16 byte orders preserve source offsets for wide, combining, invalid, and truncated units.
    Encoded delimiters split rows at their complete source byte ranges.
    */
    #[test]
    fn unicode_codecs_keep_grapheme_and_invalid_unit_boundaries() {
        let utf8_data = "e\u{301}界\nX".as_bytes();
        let utf8 = layout(1, false, b"\n", TextCodec::Utf8);
        let mut index = TextIndex::default();
        let mut reads = Vec::new();
        /* Visible widths replace controls and retain combining and wide grapheme behavior. */
        assert_eq!(visible_text_width("\0"), 1);
        assert_eq!(visible_text_width("e\u{301}"), 1);
        assert_eq!(visible_text_width("界"), 2);
        assert_eq!(
            index
                .next(
                    utf8,
                    utf8_data.len() as u64,
                    0,
                    reader(utf8_data, &mut reads)
                )
                .unwrap(),
            3
        );
        assert_eq!(
            index
                .next(
                    utf8,
                    utf8_data.len() as u64,
                    3,
                    reader(utf8_data, &mut reads)
                )
                .unwrap(),
            7
        );
        assert_eq!(
            index
                .next(
                    utf8,
                    utf8_data.len() as u64,
                    6,
                    reader(utf8_data, &mut reads)
                )
                .unwrap(),
            7
        );

        /* Invalid UTF-8 advances by one source byte without consuming later valid input. */
        let invalid = [b'A', 0xf0, 0x9f, b'B'];
        assert_eq!(
            index
                .next(utf8, invalid.len() as u64, 0, reader(&invalid, &mut reads))
                .unwrap(),
            1
        );
        assert_eq!(
            index
                .next(utf8, invalid.len() as u64, 1, reader(&invalid, &mut reads))
                .unwrap(),
            2
        );

        /* Both UTF-16 byte orders preserve combining, wide, delimiter, truncated, and invalid unit ranges. */
        for codec in [TextCodec::Utf16Le, TextCodec::Utf16Be] {
            let data = codec.encode("e\u{301}界\r\nX");
            let layout = layout(1, false, b"\r\n", codec);
            index.reset();
            assert_eq!(
                index
                    .next(layout, data.len() as u64, 0, reader(&data, &mut reads))
                    .unwrap(),
                4
            );
            assert_eq!(
                index
                    .next(layout, data.len() as u64, 4, reader(&data, &mut reads))
                    .unwrap(),
                10
            );
            assert_eq!(
                index
                    .next(layout, data.len() as u64, 6, reader(&data, &mut reads))
                    .unwrap(),
                10
            );

            let mut truncated = codec.encode("A");
            truncated.push(0xff);
            index.reset();
            assert_eq!(
                index
                    .next(
                        layout,
                        truncated.len() as u64,
                        0,
                        reader(&truncated, &mut reads)
                    )
                    .unwrap(),
                2
            );
            assert_eq!(
                index
                    .next(
                        layout,
                        truncated.len() as u64,
                        2,
                        reader(&truncated, &mut reads)
                    )
                    .unwrap(),
                3
            );

            /*
            Invalid high and low surrogates each advance by one complete UTF-16 code unit.
            The following ASCII unit remains an independent scalar boundary.
            */
            let units = [0xd800_u16, 0x0041, 0xdc00];
            let invalid: Vec<u8> = units
                .into_iter()
                .flat_map(|unit| match codec {
                    TextCodec::Utf16Le => unit.to_le_bytes(),
                    TextCodec::Utf16Be => unit.to_be_bytes(),
                    _ => unreachable!(),
                })
                .collect();
            index.reset();
            assert_eq!(
                index
                    .next(
                        layout,
                        invalid.len() as u64,
                        0,
                        reader(&invalid, &mut reads)
                    )
                    .unwrap(),
                2
            );
            assert_eq!(
                index
                    .next(
                        layout,
                        invalid.len() as u64,
                        2,
                        reader(&invalid, &mut reads)
                    )
                    .unwrap(),
                4
            );
        }
    }

    /*
    A first wide grapheme remains one row even when configured width is one.
    A following tab starts the next row without subtracting an excessive column from the width.
    */
    #[test]
    fn wide_grapheme_before_tab_starts_a_safe_following_row() {
        let mut reads = Vec::new();
        for codec in [TextCodec::Utf8, TextCodec::Utf16Le] {
            let data = codec.encode("界\tX");
            let layout = layout(1, true, b"\n", codec);
            let mut index = TextIndex::default();
            let wide_end = codec.encode("界").len() as u64;
            let tab_end = wide_end + codec.encode("\t").len() as u64;
            assert_eq!(
                index
                    .next(layout, data.len() as u64, 0, reader(&data, &mut reads))
                    .unwrap(),
                wide_end
            );
            assert_eq!(
                index
                    .next(
                        layout,
                        data.len() as u64,
                        wide_end,
                        reader(&data, &mut reads)
                    )
                    .unwrap(),
                tab_end
            );
        }
    }

    /*
    Split UTF-8 scalars, UTF-16 pairs, encoded CRLF, and large combining clusters exercise the 64 KiB source edge.
    Every reported row boundary remains scalar-safe and makes forward progress.
    */
    #[test]
    fn unicode_read_edges_keep_scalar_safe_forward_progress() {
        /* A UTF-8 scalar crosses the first 64 KiB edge and begins the next forced row. */
        let mut utf8 = vec![b'x'; READ_BYTES - 2];
        utf8.extend_from_slice("😀\r\nZ".as_bytes());
        let utf8_layout = layout(usize::MAX, false, b"\r\n", TextCodec::Utf8);
        let mut index = TextIndex::default();
        let mut reads = Vec::new();
        let first = index
            .next(utf8_layout, utf8.len() as u64, 0, reader(&utf8, &mut reads))
            .unwrap();
        assert_eq!(first, (READ_BYTES - 2) as u64);
        assert!(std::str::from_utf8(&utf8[..first as usize]).is_ok());
        let second = index
            .next(
                utf8_layout,
                utf8.len() as u64,
                first,
                reader(&utf8, &mut reads),
            )
            .unwrap();
        assert_eq!(second, (READ_BYTES + 4) as u64);
        assert!(reads.iter().all(|(_, count)| *count <= READ_BYTES));

        /* A UTF-16 surrogate pair crosses the same edge without a half-unit row boundary. */
        let mut utf16 = TextCodec::Utf16Le.encode(&"x".repeat((READ_BYTES - 2) / 2));
        utf16.extend_from_slice(&TextCodec::Utf16Le.encode("😀\r\nZ"));
        let utf16_layout = layout(usize::MAX, false, b"\r\n", TextCodec::Utf16Le);
        index.reset();
        reads.clear();
        let first = index
            .next(
                utf16_layout,
                utf16.len() as u64,
                0,
                reader(&utf16, &mut reads),
            )
            .unwrap();
        assert_eq!(first, (READ_BYTES - 2) as u64);
        assert_eq!(first % 2, 0);
        let second = index
            .next(
                utf16_layout,
                utf16.len() as u64,
                first,
                reader(&utf16, &mut reads),
            )
            .unwrap();
        assert_eq!(second, (READ_BYTES + 6) as u64);

        /* One oversized grapheme splits into scalar-safe fragments and successive bounded rows. */
        let combining = format!("a{}Z", "\u{301}".repeat(MAX_TEXT_ROW_BYTES));
        let bytes = combining.as_bytes();
        let (_, segments) = decoded_segments(bytes, TextCodec::Utf8, true);
        assert!(segments.len() > 2);
        assert_eq!(segments.first().unwrap().source_start, 0);
        assert_eq!(segments.last().unwrap().source_end, bytes.len());
        assert!(
            segments
                .windows(2)
                .all(|pair| pair[0].source_end == pair[1].source_start)
        );
        assert!(segments.iter().all(|segment| {
            segment.source_end - segment.source_start <= MAX_GRAPHEME_BYTES
                && std::str::from_utf8(&bytes[segment.source_start..segment.source_end]).is_ok()
        }));
        index.reset();
        let mut start = 0;
        let mut rows = 0;
        while start < bytes.len() as u64 {
            let next = index
                .next(
                    utf8_layout,
                    bytes.len() as u64,
                    start,
                    reader(bytes, &mut reads),
                )
                .unwrap();
            assert!(next > start);
            assert!(next - start <= MAX_TEXT_ROW_BYTES as u64);
            assert!(std::str::from_utf8(&bytes[..next as usize]).is_ok());
            start = next;
            rows += 1;
        }
        assert!(rows >= 3);
    }

    /*
    Finite rows replay an unfinished tail and recognize encoded CRLF across a 64 KiB callback edge.
    A row with unlimited display width stops at the 64 KiB byte cap before a split delimiter completes.
    */
    #[test]
    fn unicode_crlf_delimiters_cross_read_edges() {
        /* Build UTF-8 and both UTF-16 cases with CRLF divided by the first physical read edge. */
        let mut cases = Vec::new();
        let mut utf8 = vec![b'x'; READ_BYTES - 1];
        utf8.extend_from_slice(b"\r\nZ");
        cases.push((TextCodec::Utf8, utf8, 80, (READ_BYTES + 1) as u64));
        for codec in [TextCodec::Utf16Le, TextCodec::Utf16Be] {
            let mut data = codec.encode(&"x".repeat((READ_BYTES - 2) / 2));
            data.extend_from_slice(&codec.encode("\r\nZ"));
            cases.push((codec, data, 40, (READ_BYTES + 2) as u64));
        }

        for (codec, data, width, expected) in cases {
            /* Finite rows replay the unfinished row and consume the complete delimiter. */
            let finite = layout(width, false, b"\r\n", codec);
            let mut index = TextIndex::default();
            let mut reads = Vec::new();
            assert_eq!(
                index
                    .row_at(
                        finite,
                        data.len() as u64,
                        expected,
                        reader(&data, &mut reads),
                        never_cancel,
                    )
                    .unwrap(),
                Outcome::Completed(expected)
            );
            assert!(reads.iter().all(|(_, count)| *count <= READ_BYTES));
            assert!(reads.contains(&(0, READ_BYTES)));

            /* An unlimited display width still uses the 64 KiB forced Unicode row boundary. */
            let capped = layout(usize::MAX, false, b"\r\n", codec);
            let mut index = TextIndex::default();
            reads.clear();
            assert_eq!(
                index
                    .next(capped, data.len() as u64, 0, reader(&data, &mut reads))
                    .unwrap(),
                READ_BYTES as u64
            );
        }
    }

    /*
    Persistent cancellation keeps each completed CP437 chunk for a later query.
    Local replay completes one read before cancellation and never returns its partial offset.
    Callback failures reset all persistent state and preserve the original error.
    */
    #[test]
    fn cancellation_retains_chunks_hides_local_answers_and_resets_errors() {
        let data = vec![b'x'; READ_BODY_BYTES as usize * 3 + 137];
        let layout = layout(80, false, b"\n", TextCodec::Cp437);
        let target = data.len() as u64 - 1;

        /* Cancellation before the first read retains only the initialized source contract. */
        let mut index = TextIndex::with_limits(1_024, 256);
        let mut reads = Vec::new();
        assert_eq!(
            index
                .row_at(
                    layout,
                    data.len() as u64,
                    target,
                    reader(&data, &mut reads),
                    || { Ok(true) }
                )
                .unwrap(),
            Outcome::Canceled
        );
        assert!(reads.is_empty());
        assert_eq!(index.progress.pos, 0);
        assert_eq!(index.checkpoints, [0]);

        /* Two completed chunks remain valid when the third persistent poll cancels the query. */
        let mut polls = 0;
        assert_eq!(
            index
                .row_at(
                    layout,
                    data.len() as u64,
                    target,
                    reader(&data, &mut reads),
                    || {
                        polls += 1;
                        Ok(polls == 3)
                    }
                )
                .unwrap(),
            Outcome::Canceled
        );
        assert_eq!(reads.len(), 2);
        let retained_progress = index.progress.pos;
        let retained_checkpoints = index.checkpoints.clone();
        assert_eq!(retained_progress, READ_BODY_BYTES * 2);
        assert!(retained_checkpoints.iter().any(|offset| *offset != 0));

        /* The next query starts its persistent work at the retained position and returns the exact row. */
        reads.clear();
        assert_eq!(
            index
                .row_at(
                    layout,
                    data.len() as u64,
                    target,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(target / 80 * 80)
        );
        assert_eq!(reads.first().map(|read| read.0), Some(retained_progress));
        assert!(index.checkpoints.starts_with(&retained_checkpoints));
        assert!(reads.iter().all(|(_, count)| *count <= READ_BYTES));

        /* Previous also cancels before reading and preserves completed persistent chunks for resume. */
        let mut previous_index = TextIndex::with_limits(1_024, 256);
        reads.clear();
        assert_eq!(
            previous_index
                .previous(
                    layout,
                    data.len() as u64,
                    target,
                    5,
                    reader(&data, &mut reads),
                    || Ok(true),
                )
                .unwrap(),
            Outcome::Canceled
        );
        assert!(reads.is_empty());
        polls = 0;
        assert_eq!(
            previous_index
                .previous(
                    layout,
                    data.len() as u64,
                    target,
                    5,
                    reader(&data, &mut reads),
                    || {
                        polls += 1;
                        Ok(polls == 3)
                    },
                )
                .unwrap(),
            Outcome::Canceled
        );
        let previous_restart = previous_index.progress.pos;
        assert_eq!(previous_restart, READ_BODY_BYTES * 2);
        let previous_checkpoints = previous_index.checkpoints.clone();
        assert!(previous_checkpoints.iter().any(|offset| *offset != 0));
        reads.clear();
        let expected_previous = target / 80 * 80 - 5 * 80;
        assert_eq!(
            previous_index
                .previous(
                    layout,
                    data.len() as u64,
                    target,
                    5,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(expected_previous)
        );
        assert_eq!(reads.first().map(|read| read.0), Some(previous_restart));
        assert!(
            previous_index
                .checkpoints
                .starts_with(&previous_checkpoints)
        );

        /* Row lookup reads one replay chunk before cancellation hides its provisional answer. */
        let mut local_index = TextIndex::default();
        reads.clear();
        assert_eq!(
            local_index
                .row_at(
                    layout,
                    data.len() as u64,
                    target,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(target / 80 * 80)
        );
        let saved_progress = local_index.progress;
        let saved_stride = local_index.stride;
        let saved_next_checkpoint = local_index.next_checkpoint;
        let saved_checkpoints = local_index.checkpoints.clone();
        reads.clear();
        polls = 0;
        assert_eq!(
            local_index
                .row_at(
                    layout,
                    data.len() as u64,
                    target,
                    reader(&data, &mut reads),
                    || {
                        polls += 1;
                        Ok(polls == 2)
                    }
                )
                .unwrap(),
            Outcome::Canceled
        );
        assert_eq!(reads.len(), 1);
        assert_eq!(local_index.progress.pos, saved_progress.pos);
        assert_eq!(local_index.progress.row_start, saved_progress.row_start);
        assert_eq!(local_index.progress.column, saved_progress.column);
        assert_eq!(local_index.stride, saved_stride);
        assert_eq!(local_index.next_checkpoint, saved_next_checkpoint);
        assert_eq!(local_index.checkpoints, saved_checkpoints);

        /* Previous also reads one local chunk before cancellation hides the partial recent-row queue. */
        reads.clear();
        polls = 0;
        assert_eq!(
            local_index
                .previous(
                    layout,
                    data.len() as u64,
                    target,
                    1_000,
                    reader(&data, &mut reads),
                    || {
                        polls += 1;
                        Ok(polls == 2)
                    },
                )
                .unwrap(),
            Outcome::Canceled
        );
        assert_eq!(reads.len(), 1);
        assert_eq!(local_index.progress.pos, saved_progress.pos);
        assert_eq!(local_index.progress.row_start, saved_progress.row_start);
        assert_eq!(local_index.progress.column, saved_progress.column);
        assert_eq!(local_index.stride, saved_stride);
        assert_eq!(local_index.next_checkpoint, saved_next_checkpoint);
        assert_eq!(local_index.checkpoints, saved_checkpoints);

        /* A cancellation callback error after one chunk clears the complete index. */
        let mut failing = TextIndex::default();
        let mut error_reads = Vec::new();
        polls = 0;
        let error = failing
            .row_at(
                layout,
                data.len() as u64,
                target,
                reader(&data, &mut error_reads),
                || {
                    polls += 1;
                    if polls == 2 {
                        Err(io::Error::other("Injected cancellation failure."))
                    } else {
                        Ok(false)
                    }
                },
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "Injected cancellation failure.");
        assert_eq!(error_reads.len(), 1);
        assert_eq!(failing.layout, None);
        assert_eq!(failing.source_len, None);
        assert_eq!(failing.checkpoints, [0]);
        assert_eq!(failing.progress.pos, 0);

        /* A read error after one completed chunk follows the same complete reset contract. */
        let mut failing = TextIndex::default();
        let mut read_count = 0;
        let error = failing
            .row_at(
                layout,
                data.len() as u64,
                target,
                |_, output| {
                    read_count += 1;
                    if read_count == 2 {
                        Err(io::Error::other("Injected resumed read failure."))
                    } else {
                        output.fill(b'x');
                        Ok(())
                    }
                },
                never_cancel,
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "Injected resumed read failure.");
        assert_eq!(read_count, 2);
        assert_eq!(failing.layout, None);
        assert_eq!(failing.source_len, None);
        assert_eq!(failing.checkpoints, [0]);
        assert_eq!(failing.progress.pos, 0);
    }

    /*
    Last keeps completed chunks and resumes for every supported codec.
    A completed index performs no read or cancellation poll during a repeated last query.
    */
    #[test]
    fn last_cancellation_resumes_all_codecs_without_final_poll() {
        for codec in [
            TextCodec::Cp437,
            TextCodec::Utf8,
            TextCodec::Utf16Le,
            TextCodec::Utf16Be,
        ] {
            let data = if matches!(codec, TextCodec::Utf16Le | TextCodec::Utf16Be) {
                codec.encode(&"x".repeat(READ_BYTES + 17))
            } else {
                vec![b'x'; READ_BYTES * 2 + 17]
            };
            let layout = layout(80, false, b"\n", codec);
            let mut index = TextIndex::with_limits(1_024, 256);
            let mut reads = Vec::new();
            let mut polls = 0;

            /* Cancel before the second read and retain the first complete scan window. */
            assert_eq!(
                index
                    .last(layout, data.len() as u64, reader(&data, &mut reads), || {
                        polls += 1;
                        Ok(polls == 2)
                    })
                    .unwrap(),
                Outcome::Canceled
            );
            let restart = index.progress.pos;
            let retained_checkpoints = index.checkpoints.clone();
            assert!(restart > 0 && restart < data.len() as u64);
            assert_eq!(reads.len(), 1);
            assert!(retained_checkpoints.iter().any(|offset| *offset != 0));

            /* Resume at the retained position and return the codec-specific final-row convention. */
            reads.clear();
            let expected = if codec == TextCodec::Cp437 {
                (data.len() as u64 - 1) / 80 * 80
            } else {
                data.len() as u64
            };
            assert_eq!(
                index
                    .last(
                        layout,
                        data.len() as u64,
                        reader(&data, &mut reads),
                        never_cancel,
                    )
                    .unwrap(),
                Outcome::Completed(expected)
            );
            assert_eq!(reads.first().map(|read| read.0), Some(restart));
            assert!(index.checkpoints.starts_with(&retained_checkpoints));
            assert!(reads.iter().all(|(_, count)| *count <= READ_BYTES));

            /* A repeated completed query must not call either callback. */
            let mut final_polls = 0;
            assert_eq!(
                index
                    .last(
                        layout,
                        data.len() as u64,
                        |_, _| panic!("A completed last query must not read."),
                        || {
                            final_polls += 1;
                            Ok(false)
                        },
                    )
                    .unwrap(),
                Outcome::Completed(expected)
            );
            assert_eq!(final_polls, 0);
        }
    }

    /*
    This helper builds one old CP437 index and applies one successful logical edit.
    The invalidated result must match both an independent offset and a fresh index.
    */
    fn check_cp437_edit(
        before: &[u8],
        after: &[u8],
        change_start: u64,
        target: u64,
        expected: u64,
    ) {
        let layout = layout(8, false, b"\r\n", TextCodec::Cp437);
        let mut index = TextIndex::with_limits(8, 8);
        let mut reads = Vec::new();
        assert!(matches!(
            index
                .last(
                    layout,
                    before.len() as u64,
                    reader(before, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(_)
        ));
        index.invalidate_from(change_start, after.len() as u64);
        assert_eq!(index.source_len, Some(after.len() as u64));

        /* Compare the retained-index answer with both independent and rebuilt answers. */
        reads.clear();
        let result = index
            .row_at(
                layout,
                after.len() as u64,
                target,
                reader(after, &mut reads),
                never_cancel,
            )
            .unwrap();
        assert_eq!(result, Outcome::Completed(expected));
        let mut fresh = TextIndex::with_limits(8, 8);
        let mut fresh_reads = Vec::new();
        assert_eq!(
            result,
            fresh
                .row_at(
                    layout,
                    after.len() as u64,
                    target,
                    reader(after, &mut fresh_reads),
                    never_cancel,
                )
                .unwrap()
        );
        assert!(reads.iter().all(|(_, count)| *count <= READ_BYTES));
    }

    /*
    CP437 invalidation covers replacement, insertion, deletion, append, truncate, and offset zero.
    CRLF creation and removal at a wrap checkpoint rebuild the affected boundary.
    */
    #[test]
    fn cp437_invalidation_adopts_edit_lengths_and_preserves_earlier_progress() {
        check_cp437_edit(b"abcdefghij", b"abcdefg\r\nj", 7, 9, 9);
        check_cp437_edit(b"abcdefg\r\nj", b"abcdefghij", 7, 9, 8);
        check_cp437_edit(b"abcdefgh", b"ab\r\ncdefgh", 2, 9, 4);
        check_cp437_edit(b"ab\r\ncdefgh", b"abcdefgh", 2, 7, 0);
        check_cp437_edit(b"abc", b"abc\r\nxy", 3, 6, 5);
        check_cp437_edit(b"abc\r\nxy", b"abc", 3, 2, 0);
        check_cp437_edit(b"abcdefgh", b"\r\nabcdef", 0, 7, 2);

        /* An edit beyond indexed progress leaves the complete known prefix unchanged. */
        let mut data = vec![b'x'; 10_000];
        let layout = layout(8, false, b"\r\n", TextCodec::Cp437);
        let mut index = TextIndex::with_limits(64, 8);
        let mut reads = Vec::new();
        assert_eq!(
            index
                .row_at(
                    layout,
                    data.len() as u64,
                    100,
                    reader(&data, &mut reads),
                    never_cancel
                )
                .unwrap(),
            Outcome::Completed(96)
        );
        let progress = index.progress;
        let checkpoints = index.checkpoints.clone();
        data[9_000] = b'\n';
        index.invalidate_from(9_000, data.len() as u64);
        assert_eq!(index.progress.pos, progress.pos);
        assert_eq!(index.checkpoints, checkpoints);
        assert_eq!(
            index
                .row_at(
                    layout,
                    data.len() as u64,
                    100,
                    reader(&data, &mut reads),
                    never_cancel
                )
                .unwrap(),
            Outcome::Completed(96)
        );

        /* An unexplained query-length change resets compacted state before the new query. */
        let old = vec![b'x'; 4_096];
        let mut changed = old.clone();
        changed.push(b'x');
        let mut index = TextIndex::with_limits(64, 4);
        assert_eq!(
            index
                .row_at(
                    layout,
                    old.len() as u64,
                    4_000,
                    reader(&old, &mut reads),
                    never_cancel
                )
                .unwrap(),
            Outcome::Completed(4_000)
        );
        assert!(index.stride > 64);
        assert_eq!(
            index
                .row_at(
                    layout,
                    changed.len() as u64,
                    0,
                    reader(&changed, &mut reads),
                    never_cancel
                )
                .unwrap(),
            Outcome::Completed(0)
        );
        assert_eq!(index.stride, 64);
        assert_eq!(index.checkpoints, [0]);
        assert_eq!(index.progress.pos, 1);
    }

    /*
    A compacted multi-megabyte index keeps its stride and valid checkpoints before one suffix edit.
    Rebuilding reads only from the retained restart point and returns an independent exact offset.
    */
    #[test]
    fn compacted_suffix_invalidation_reuses_prefix_and_reads_only_suffix() {
        let mut data = vec![b'x'; 5 * 1024 * 1024 + 37];
        let layout = layout(80, false, b"\n", TextCodec::Cp437);
        let mut index = TextIndex::with_limits(64 * 1024, 8);
        let mut reads = Vec::new();
        assert!(matches!(
            index
                .last(
                    layout,
                    data.len() as u64,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(_)
        ));
        let compacted_stride = index.stride;
        let old_checkpoints = index.checkpoints.clone();
        assert!(compacted_stride > 64 * 1024);

        /* Insert one delimiter after the retained prefix and adopt the longer source length. */
        let change = 4 * 1024 * 1024 + 17;
        let affected = change as u64 - 1;
        let expected_retained: Vec<u64> = old_checkpoints
            .iter()
            .copied()
            .filter(|offset| *offset < affected)
            .collect();
        data.insert(change, b'\n');
        index.invalidate_from(change as u64, data.len() as u64);
        let restart = index.progress.pos;
        let retained = index.checkpoints.clone();
        assert!(retained.len() > 1);
        assert!(retained.len() < old_checkpoints.len());
        assert_eq!(retained, expected_retained);
        assert!(restart > 0);
        assert_eq!(index.stride, compacted_stride);
        assert_eq!(retained.last().copied(), Some(restart));
        assert_eq!(index.source_len, Some(data.len() as u64));

        /* Rebuild the suffix and compare it with one fresh scan. */
        reads.clear();
        let target = data.len() as u64 - 1;
        let row_after_delimiter = change as u64 + 1;
        let expected = row_after_delimiter + (target - row_after_delimiter) / 80 * 80;
        let result = index
            .row_at(
                layout,
                data.len() as u64,
                target,
                reader(&data, &mut reads),
                never_cancel,
            )
            .unwrap();
        assert_eq!(result, Outcome::Completed(expected));
        assert_eq!(reads.first().map(|read| read.0), Some(restart));
        assert!(
            reads
                .iter()
                .all(|(start, count)| { *start >= restart && *count <= READ_BYTES })
        );
        let suffix_chunks = (data.len() as u64 - restart).div_ceil(READ_BODY_BYTES);
        let replay_chunks = index
            .stride
            .saturating_add(layout.max_row_bytes())
            .div_ceil(READ_BODY_BYTES);
        let read_ceiling = suffix_chunks.saturating_add(replay_chunks);
        assert!(u64::try_from(reads.len()).unwrap() <= read_ceiling);
        let mut fresh = TextIndex::default();
        let mut fresh_reads = Vec::new();
        assert_eq!(
            result,
            fresh
                .row_at(
                    layout,
                    data.len() as u64,
                    target,
                    reader(&data, &mut fresh_reads),
                    never_cancel,
                )
                .unwrap()
        );
    }

    /*
    Unicode invalidation keeps checkpoints only before its 4 KiB grapheme carry area.
    A combining mark inserted near a read boundary rebuilds from the retained earlier row.
    */
    #[test]
    fn unicode_invalidation_uses_grapheme_lookbehind_near_read_boundary() {
        let mut data = vec![b'x'; READ_BYTES * 2 + 101];
        let layout = layout(80, false, b"\n", TextCodec::Utf8);
        let mut index = TextIndex::with_limits(1_024, 256);
        let mut reads = Vec::new();
        assert!(matches!(
            index
                .last(
                    layout,
                    data.len() as u64,
                    reader(&data, &mut reads),
                    never_cancel,
                )
                .unwrap(),
            Outcome::Completed(_)
        ));

        /* Insert one combining scalar immediately before the first read boundary. */
        let change = READ_BYTES - 1;
        data.splice(change..change, [0xcc, 0x81]);
        index.invalidate_from(change as u64, data.len() as u64);
        let affected = change as u64 - MAX_GRAPHEME_BYTES as u64;
        let restart = index.progress.pos;
        assert!(restart > 0 && restart < affected);
        assert!(index.checkpoints.iter().all(|offset| *offset < affected));
        assert_eq!(index.source_len, Some(data.len() as u64));

        /* The retained index and a fresh index must return the same exact row. */
        reads.clear();
        let target = change as u64 + 1_000;
        let result = index
            .row_at(
                layout,
                data.len() as u64,
                target,
                reader(&data, &mut reads),
                never_cancel,
            )
            .unwrap();
        assert_eq!(result, Outcome::Completed(66_482));
        assert_eq!(reads.first().map(|read| read.0), Some(restart));
        assert!(reads.iter().all(|(_, count)| *count <= READ_BYTES));
        let mut fresh = TextIndex::default();
        let mut fresh_reads = Vec::new();
        assert_eq!(
            result,
            fresh
                .row_at(
                    layout,
                    data.len() as u64,
                    target,
                    reader(&data, &mut fresh_reads),
                    never_cancel,
                )
                .unwrap()
        );
    }

    /*
    PagedFile supplies current logical edit bytes through the existing exact-fill adapter.
    A later external source replacement returns its original error and resets the index.
    */
    #[test]
    fn paged_logical_edit_and_changed_source_follow_index_contract() {
        let fixture = Fixture::new();
        let path = fixture.0.join("paged-edit.bin");
        fs::write(&path, b"abcd\nefgh").unwrap();
        let mut paged = PagedFile::open(&path).unwrap();
        let layout = layout(80, false, b"\n", TextCodec::Cp437);
        let mut index = TextIndex::default();
        assert_eq!(
            index
                .row_at(layout, paged.len(), 8, paged_reader(&paged), never_cancel)
                .unwrap(),
            Outcome::Completed(5)
        );

        /* Delete the delimiter in logical edit state and adopt the new logical length. */
        let cursor = PagedEditCursor {
            offset: 4,
            top: 0,
            low_nibble: false,
        };
        paged.begin_edit().unwrap();
        assert!(
            paged
                .splice_bytes(4, 1, b"", cursor, cursor, false)
                .unwrap()
        );
        index.invalidate_from(4, paged.len());
        assert_eq!(
            index
                .row_at(layout, paged.len(), 7, paged_reader(&paged), never_cancel)
                .unwrap(),
            Outcome::Completed(0)
        );

        /* Replace the pathname source and verify the exact PagedFile validation failure. */
        let old_path = fixture.0.join("old-paged-edit.bin");
        fs::rename(&path, &old_path).unwrap();
        fs::write(&path, b"abcdefgh").unwrap();
        let error = index
            .row_at(layout, paged.len(), 7, paged_reader(&paged), never_cancel)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "The source path identifies a different file. Reopen the source."
        );
        assert_eq!(index.layout, None);
        assert_eq!(index.source_len, None);
        assert_eq!(index.checkpoints, [0]);
        assert_eq!(index.progress.pos, 0);
    }

    /*
    High offsets exercise checked next-checkpoint arithmetic without large files or allocations.
    Excessive change offsets first clamp to both the old and new source lengths.
    */
    #[test]
    fn invalidation_bounds_offsets_and_saturates_checkpoint_arithmetic() {
        let layout = layout(80, false, b"\n", TextCodec::Cp437);
        let mut index = TextIndex::with_limits(u64::MAX - 64, 4);
        index.layout = Some(layout);
        index.source_len = Some(u64::MAX);
        index.stride = u64::MAX - 64;
        index.checkpoints = vec![0, u64::MAX - 32];
        index.progress = ScanState {
            pos: u64::MAX,
            row_start: u64::MAX - 32,
            column: 0,
        };
        index.invalidate_from(u64::MAX, u64::MAX);
        assert_eq!(index.progress.pos, u64::MAX - 32);
        assert_eq!(index.next_checkpoint, u64::MAX);

        /* Clamp an excessive edit offset to the shorter resulting length before lookbehind. */
        index.source_len = Some(100);
        index.stride = 64;
        index.checkpoints = vec![0, 40, 80];
        index.progress = ScanState {
            pos: 100,
            row_start: 80,
            column: 20,
        };
        index.invalidate_from(u64::MAX, 50);
        assert_eq!(index.source_len, Some(50));
        assert_eq!(index.checkpoints, [0, 40]);
        assert_eq!(index.progress.pos, 40);
        assert_eq!(index.next_checkpoint, 64);
    }

    /*
    This generated callback serves a local row near u64::MAX without allocating or scanning its prefix.
    Range assertions prove that every bounded request remains inside the supplied source length.
    */
    #[test]
    fn high_u64_next_uses_only_one_valid_local_range() {
        let len = u64::MAX;
        let start = len - 100;
        let byte_layout = layout(10, false, b"\n", TextCodec::Cp437);
        let mut index = TextIndex::default();
        let mut reads = Vec::new();
        /* A normal local row near u64::MAX advances by its exact configured byte width. */
        let next = index
            .next(byte_layout, len, start, |offset, output| {
                let count = u64::try_from(output.len()).unwrap();
                assert!(offset <= len);
                assert!(count <= len - offset);
                reads.push((offset, output.len()));
                output.fill(b'x');
                Ok(())
            })
            .unwrap();
        assert_eq!(next, start + 10);
        assert_eq!(reads.len(), 1);
        assert!(reads[0].1 <= READ_BYTES);

        /*
        Both byte and Unicode scans reach the saturated EOF from a two-byte final row.
        Neither scan requests a range beyond the supplied u64 length.
        */
        for codec in [TextCodec::Cp437, TextCodec::Utf8] {
            let mut index = TextIndex::default();
            let mut reads = Vec::new();
            let result = index
                .next(
                    layout(10, false, b"\n", codec),
                    len,
                    len - 2,
                    |offset, output| {
                        let count = u64::try_from(output.len()).unwrap();
                        assert!(offset <= len);
                        assert!(count <= len - offset);
                        reads.push((offset, output.len()));
                        output.fill(b'x');
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(result, len);
            assert_eq!(reads, [(len - 2, 2)]);
        }
    }
}
