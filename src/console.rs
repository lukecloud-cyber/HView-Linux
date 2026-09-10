/*
This module owns Linux terminal mode, bounded input parsing, screen output, and macro key delivery.
Physical terminal input and stored macro input share one Key shape after their separate input boundaries.
*/
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
compile_error!("HView-Linux currently supports Linux on x86-64.");

/*
These standard types store terminal state, pending input, formatted output, and bounded macro delays.
The module uses direct libc calls because no external terminal dependency is necessary.
*/
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::ffi::{c_int, c_void};
use std::fmt::Write as _;
use std::io::{self, Write as _};
use std::time::{Duration, Instant};

/*
These Linux ABI constants describe stdin polling, raw terminal flags, window queries, and control-character indexes.
The values match the supported x86-64 GNU host.
*/
const STDIN: c_int = 0;
const POLLIN: i16 = 0x001;
const EINTR: i32 = 4;
const TCSAFLUSH: c_int = 2;
const TIOCGWINSZ: usize = 0x5413;
const BRKINT: u32 = 0o000002;
const ICRNL: u32 = 0o000400;
const INPCK: u32 = 0o000020;
const ISTRIP: u32 = 0o000040;
const IXON: u32 = 0o002000;
const OPOST: u32 = 0o000001;
const CS8: u32 = 0o000060;
const ECHO: u32 = 0o000010;
const ICANON: u32 = 0o000002;
const ISIG: u32 = 0o000001;
const IEXTEN: u32 = 0o100000;
const VTIME: usize = 5;
const VMIN: usize = 6;

/*
These C-compatible records carry terminal settings, dimensions, and poll results across the libc boundary.
Unit tests verify the host layouts before normal terminal operations depend on them.
*/
#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    input: u32,
    output: u32,
    control: u32,
    local: u32,
    line: u8,
    chars: [u8; 32],
    input_speed: u32,
    output_speed: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct WindowSize {
    rows: u16,
    columns: u16,
    x_pixels: u16,
    y_pixels: u16,
}

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    returned: i16,
}

/*
These libc functions provide the small Linux terminal interface used by Console.
Callers check every operational result and preserve the returned operating-system error.
*/
#[link(name = "c")]
unsafe extern "C" {
    fn isatty(fd: c_int) -> c_int;
    fn tcgetattr(fd: c_int, termios: *mut Termios) -> c_int;
    fn tcsetattr(fd: c_int, action: c_int, termios: *const Termios) -> c_int;
    fn ioctl(fd: c_int, request: usize, ...) -> c_int;
    fn poll(fds: *mut PollFd, count: usize, timeout: c_int) -> c_int;
    fn read(fd: c_int, buffer: *mut c_void, count: usize) -> isize;
}

/*
This check rejects redirected input or output before raw terminal state changes.
Interactive operation requires both standard descriptors to refer to terminals.
*/
pub fn redirected() -> bool {
    unsafe { isatty(0) == 0 || isatty(1) == 0 }
}

/*
Console owns the original terminal state and cached dimensions for one application run.
It also keeps macro playback and physical keys that arrive while a macro delay runs.
*/
pub struct Console {
    old_termios: Termios,
    width: Cell<usize>,
    height: Cell<usize>,
    playback: RefCell<Option<crate::macros::Playback>>,
    pending_keys: RefCell<VecDeque<Key>>,
}

/*
Key stores one application key code, its decoded character, and Windows-compatible modifier bits.
Control uses bits 4 and 8. Alt uses bits 1 and 2. Shift uses bit 16.
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Key {
    pub code: u16,
    pub character: char,
    pub control: u32,
}

impl Key {
    /*
    This predicate accepts one mapped Alt letter and rejects Control, Shift, or mixed modifier input.
    The code comparison is case independent because the parser normalizes ASCII letter key codes.
    */
    pub fn is_alt(self, letter: u8) -> bool {
        self.control & 3 != 0
            && self.control & !3 == 0
            && self.code == u16::from(letter.to_ascii_uppercase())
    }

    /*
    This predicate permits unmodified text and Shift text while rejecting Control and Alt text.
    Prompts, Hex editing, navigation letters, and character menus use the same input boundary.
    */
    pub fn accepts_text(self) -> bool {
        self.control & 15 == 0 && !self.character.is_control()
    }
}

/*
This bounded delay keeps macro playback responsive to physical Escape input.
Other physical keys enter the pending queue for delivery after the macro event.
*/
fn wait_delay(delay_ms: u32, mut cancelled: impl FnMut() -> io::Result<bool>) -> io::Result<bool> {
    let start = Instant::now();
    let delay = Duration::from_millis(u64::from(delay_ms));
    loop {
        if cancelled()? {
            return Ok(false);
        }
        let remaining = delay.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Ok(true);
        }
        // ponytail: Poll every 20 ms until Linux exposes a suitable input wait here.
        std::thread::sleep(remaining.min(Duration::from_millis(20)));
    }
}

/*
This formatter emits terminal-safe text within a fixed cell count.
Known one-cell characters remain visible, while controls and unknown-width Unicode use safe replacements.
*/
fn visible(text: &str, width: usize) -> String {
    let mut output = String::new();
    let mut cells = 0;
    for ch in text.chars() {
        let known_cell = ch.is_ascii()
            || (0..=0xff).any(|byte| crate::editor::cp437(byte) == ch)
            || matches!(ch as u32, 0x2190..=0x21ff | 0x2500..=0x259f);
        let text = if ch.is_control() {
            "�".to_owned()
        } else if known_cell {
            ch.to_string()
        } else {
            format!("\\u{{{:X}}}", ch as u32)
        };
        let count = text.chars().count();
        if cells + count > width {
            break;
        }
        output.push_str(&text);
        cells += count;
    }
    output
}

/*
This public wrapper escapes complete display text without a width limit.
Operational native paths stay outside this display-only conversion.
*/
pub fn safe_text(text: &str) -> String {
    visible(text, usize::MAX)
}

/*
This query reads current terminal dimensions and rejects unusable zero-sized results.
Rendering and resize detection use the same validated values.
*/
fn screen_size() -> io::Result<(usize, usize)> {
    let mut size = WindowSize::default();
    if unsafe { ioctl(1, TIOCGWINSZ, &mut size) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if size.columns == 0 || size.rows == 0 {
        return Err(io::Error::other("The terminal size is zero."));
    }
    Ok((usize::from(size.columns), usize::from(size.rows)))
}

/*
This decoder converts xterm modifier parameters into the established Windows-compatible modifier bits.
The conversion keeps Alt separate from both supported Control bits.
*/
fn modifier_state(value: u16) -> u32 {
    let bits = value.saturating_sub(1);
    (u32::from(bits & 1 != 0) * 16)
        | (u32::from(bits & 2 != 0) * 2)
        | (u32::from(bits & 4 != 0) * 8)
}

/*
This converter maps printable ASCII letters and digits to stable application key codes.
Other characters keep their character value but do not receive a command code.
*/
fn key_code(byte: u8) -> u16 {
    if byte.is_ascii_alphabetic() {
        u16::from(byte.to_ascii_uppercase())
    } else if byte.is_ascii_digit() || byte == b' ' {
        u16::from(byte)
    } else {
        0
    }
}

/*
This converter turns one raw ASCII control byte into its letter code and Control state.
The character remains the original control value so text paths cannot insert it.
*/
fn control_key(byte: u8) -> Key {
    Key {
        code: u16::from(b'A' + byte - 1),
        character: char::from(byte),
        control: 8,
    }
}

/*
This converter creates one raw Escape-prefixed Alt key from its following byte.
ASCII letters retain a command code, while non-ASCII bytes become safe replacement text.
*/
fn alt_key(byte: u8) -> Key {
    Key {
        code: key_code(byte),
        character: if byte.is_ascii() {
            char::from(byte)
        } else {
            '\u{fffd}'
        },
        control: 2,
    }
}

/*
This parser converts one complete CSI or SS3 body into an application key.
The physical filter consumes recognized function-key sequences without dispatching their actions.
*/
fn csi_key(sequence: &[u8]) -> Option<Key> {
    let final_byte = *sequence.last()?;
    let body = std::str::from_utf8(&sequence[..sequence.len() - 1]).ok()?;
    let values: Vec<u16> = body
        .split(';')
        .map(|value| {
            if value.is_empty() {
                Ok(1)
            } else {
                value.parse()
            }
        })
        .collect::<Result<_, _>>()
        .ok()?;
    let control = modifier_state(*values.get(1).unwrap_or(&1));
    let code = match final_byte {
        b'A' => 38,
        b'B' => 40,
        b'C' => 39,
        b'D' => 37,
        b'H' => 36,
        b'F' => 35,
        b'P' => 112,
        b'Q' => 113,
        b'R' => 114,
        b'S' => 115,
        b'~' => match values.first().copied().unwrap_or(0) {
            1 | 7 => 36,
            4 | 8 => 35,
            5 => 33,
            6 => 34,
            11 => 112,
            12 => 113,
            13 => 114,
            14 => 115,
            15 => 116,
            17 => 117,
            18 => 118,
            19 => 119,
            20 => 120,
            21 => 121,
            23 => 122,
            24 => 123,
            _ => return None,
        },
        _ => return None,
    };
    Some(Key {
        code,
        character: '\0',
        control,
    })
}

/*
This physical-input filter removes parsed function keys after the terminal sequence is complete.
Stored macro scan keys do not use this filter and keep legacy compatibility.
*/
fn physical_sequence_key(sequence: &[u8]) -> Option<Key> {
    csi_key(sequence).filter(|key| !(112..=123).contains(&key.code))
}

/*
This converter maps a legacy scan code or character keycode into one application Key.
Macro playback uses this path so stored function-key records keep their historical actions.
*/
fn scan_key(scan: u16, keycode: u32, control: u32) -> Option<Key> {
    let code = match scan {
        0x3b..=0x44 => 112 + scan - 0x3b,
        0x57 => 122,
        0x58 => 123,
        0xe047 => 36,
        0xe04f => 35,
        0xe049 => 33,
        0xe051 => 34,
        0xe04b => 37,
        0xe04d => 39,
        0xe048 => 38,
        0xe050 => 40,
        1 => 27,
        0x0e => 8,
        0x1c => 13,
        _ => {
            let code = u16::try_from(keycode).ok()?;
            if code <= 0x7f {
                match code as u8 {
                    8 => 8,
                    9 => 9,
                    10 | 13 => 13,
                    27 => 27,
                    byte => key_code(byte),
                }
            } else {
                code
            }
        }
    };
    let character = if keycode <= 255 {
        let byte = keycode as u8;
        let upper = byte.to_ascii_uppercase();
        if control & 8 != 0 && (b'@'..=b'_').contains(&upper) {
            char::from(upper - b'@')
        } else if byte.is_ascii_control() {
            char::from(byte)
        } else {
            crate::editor::cp437(byte)
        }
    } else {
        '\0'
    };
    Some(Key {
        code,
        character,
        control,
    })
}

/*
This implementation manages the terminal lifecycle, input boundaries, drawing, prompts, and macro playback.
Each method preserves the original terminal state or returns an operating-system error.
*/
impl Console {
    /*
    This constructor captures the terminal, selects raw input, and enters the alternate screen.
    A partial initialization restores the terminal before it returns the original error.
    */
    pub fn new() -> io::Result<Self> {
        if redirected() {
            return Err(io::Error::other(
                "HView-Linux needs an interactive terminal.",
            ));
        }
        /*
        This section reads the current Linux terminal state and derives the required raw flags.
        The saved record remains unchanged for Drop and failed-initialization recovery.
        */
        let mut old_termios = unsafe { std::mem::zeroed() };
        if unsafe { tcgetattr(STDIN, &mut old_termios) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = old_termios;
        raw.input &= !(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
        raw.output &= !OPOST;
        raw.control |= CS8;
        raw.local &= !(ECHO | ICANON | IEXTEN | ISIG);
        raw.chars[VMIN] = 1;
        raw.chars[VTIME] = 0;
        if unsafe { tcsetattr(STDIN, TCSAFLUSH, &raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
        /*
        This section validates dimensions and publishes the alternate-screen control sequence.
        Console state becomes available only after the terminal output flush succeeds.
        */
        let initialized = (|| {
            let (width, height) = screen_size()?;
            let mut output = io::stdout().lock();
            output.write_all(b"\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H")?;
            output.flush()?;
            Ok(Self {
                old_termios,
                width: Cell::new(width),
                height: Cell::new(height),
                playback: RefCell::new(None),
                pending_keys: RefCell::new(VecDeque::new()),
            })
        })();
        /*
        If screen initialization fails, this section restores the cursor, screen, and terminal settings.
        The caller then receives the initialization error with no retained Console owner.
        */
        if initialized.is_err() {
            let mut output = io::stdout().lock();
            let _ = output.write_all(b"\x1b[?25h\x1b[?1049l");
            let _ = output.flush();
            unsafe {
                tcsetattr(STDIN, TCSAFLUSH, &old_termios);
            }
        }
        initialized
    }

    /*
    This accessor refreshes cached dimensions when the operating-system query succeeds.
    A failed refresh retains the last dimensions from a valid query.
    */
    pub fn dimensions(&self) -> (usize, usize) {
        if let Ok((width, height)) = screen_size() {
            self.width.set(width);
            self.height.set(height);
        }
        (self.width.get(), self.height.get())
    }

    /*
    This check updates cached dimensions and reports whether a new terminal size exists.
    Input polling uses the result to request a redraw without creating a key action.
    */
    fn resized(&self) -> bool {
        let Ok((width, height)) = screen_size() else {
            return false;
        };
        let changed = (width, height) != (self.width.get(), self.height.get());
        self.width.set(width);
        self.height.set(height);
        changed
    }

    /*
    These accessors select one refreshed dimension for layout calculations.
    */
    pub fn width(&self) -> usize {
        self.dimensions().0
    }

    pub fn height(&self) -> usize {
        self.dimensions().1
    }

    /*
    This renderer clears each visible row and writes one clipped frame to standard output.
    It builds the complete control sequence before one locked write and flush.
    */
    pub fn draw(&self, lines: &[String]) -> io::Result<()> {
        let (width, height) = self.dimensions();
        let mut frame = String::with_capacity(width.saturating_mul(height).saturating_add(64));
        for row in 0..height {
            write!(&mut frame, "\x1b[{};1H\x1b[2K", row + 1).unwrap();
            if let Some(line) = lines.get(row) {
                frame.push_str(&visible(line, width));
            }
        }
        let mut output = io::stdout().lock();
        output.write_all(frame.as_bytes())?;
        output.flush()
    }

    /*
    This input controller delivers a macro event, one pending physical key, or a new terminal key.
    Resize events return an empty key so the viewer can redraw without an action.
    */
    pub fn key(&self) -> io::Result<Key> {
        /*
        Macro playback uses the legacy scan conversion before physical input parsing.
        Thus, stored function-key records keep their contextual actions after physical function keys retire.
        */
        if let Some(playback) = self.playback.borrow_mut().as_mut()
            && let Some(event) = playback.next_event()
        {
            if !wait_delay(playback.delay_ms, || self.macro_cancelled())? {
                playback.cancel();
                return Ok(Key {
                    code: 27,
                    character: '\u{1b}',
                    control: 0,
                });
            }
            if event.keycode != 0 {
                return scan_key(
                    event.scan_code().map_err(io::Error::other)?.unwrap_or(0),
                    event.keycode,
                    event.control_state(),
                )
                .ok_or_else(|| io::Error::other("The macro key is not valid."));
            }
        }
        /*
        Physical keys collected during a macro delay run before new terminal polling.
        The final loop converts a terminal resize into a neutral key for the active view.
        */
        if let Some(key) = self.pending_keys.borrow_mut().pop_front() {
            return Ok(key);
        }
        loop {
            if let Some(key) = self.read_key_timeout(50)? {
                return Ok(key);
            }
            if self.resized() {
                return Ok(Key {
                    code: 0,
                    character: '\0',
                    control: 0,
                });
            }
        }
    }

    /*
    This bounded poll reads one byte and retries an interrupted Linux system call.
    Timeout, EOF, and operating-system errors remain distinct results for the input parser.
    */
    fn read_byte(&self, timeout_ms: c_int) -> io::Result<Option<u8>> {
        let mut input = PollFd {
            fd: STDIN,
            events: POLLIN,
            returned: 0,
        };
        loop {
            let ready = unsafe { poll(&mut input, 1, timeout_ms) };
            if ready == 0 {
                return Ok(None);
            }
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(EINTR) {
                    continue;
                }
                return Err(error);
            }
            let mut byte = 0u8;
            let count = unsafe { read(STDIN, (&mut byte as *mut u8).cast(), 1) };
            if count == 1 {
                return Ok(Some(byte));
            }
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "The terminal input reached EOF.",
                ));
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(EINTR) {
                return Err(error);
            }
        }
    }

    /*
    This parser handles one physical control, ASCII, or UTF-8 key from standard input.
    Escape starts the separate Alt and terminal-sequence path.
    */
    fn read_key_timeout(&self, timeout_ms: c_int) -> io::Result<Option<Key>> {
        let Some(first) = self.read_byte(timeout_ms)? else {
            return Ok(None);
        };
        if first == 0x1b {
            return self.read_escape();
        }
        if first == b'\r' || first == b'\n' {
            return Ok(Some(Key {
                code: 13,
                character: '\r',
                control: 0,
            }));
        }
        if first == 8 || first == 127 {
            return Ok(Some(Key {
                code: 8,
                character: '\u{8}',
                control: 0,
            }));
        }
        if first == b'\t' {
            return Ok(Some(Key {
                code: 9,
                character: '\t',
                control: 0,
            }));
        }
        if (1..=26).contains(&first) {
            return Ok(Some(control_key(first)));
        }
        /*
        This section reads the remaining bytes for one UTF-8 character with a short input deadline.
        Invalid input becomes one replacement character without creating a command code.
        */
        let mut bytes = vec![first];
        let length = match first {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => 1,
        };
        while bytes.len() < length {
            bytes.push(self.read_byte(30)?.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "The UTF-8 key is incomplete.")
            })?);
        }
        let character = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| text.chars().next())
            .unwrap_or('\u{fffd}');
        Ok(Some(Key {
            code: if first.is_ascii() { key_code(first) } else { 0 },
            character,
            control: 0,
        }))
    }

    /*
    This parser distinguishes plain Escape, Alt-prefixed characters, and CSI or SS3 terminal keys.
    Physical function keys are consumed here, while macro scan keys bypass this physical boundary.
    */
    fn read_escape(&self) -> io::Result<Option<Key>> {
        let Some(next) = self.read_byte(30)? else {
            return Ok(Some(Key {
                code: 27,
                character: '\u{1b}',
                control: 0,
            }));
        };
        if next != b'[' && next != b'O' {
            return Ok(Some(alt_key(next)));
        }
        /*
        This bounded sequence reader stops after one final terminal byte.
        It suppresses retired physical function keys after parsing all their bytes.
        */
        let mut sequence = Vec::with_capacity(8);
        while sequence.len() < 24 {
            let Some(byte) = self.read_byte(30)? else {
                return Ok(None);
            };
            sequence.push(byte);
            if (0x40..=0x7e).contains(&byte) {
                if let Some(key) = physical_sequence_key(&sequence) {
                    return Ok(Some(key));
                }
                break;
            }
        }
        Ok(None)
    }

    /*
    This poll lets physical Escape cancel macro delay without losing other physical keys.
    The fixed key count bounds work before the next macro event.
    */
    fn macro_cancelled(&self) -> io::Result<bool> {
        let mut cancelled = false;
        for _ in 0..64 {
            let Some(key) = self.read_key_timeout(0)? else {
                break;
            };
            if key.code == 27 {
                cancelled = true;
            } else {
                self.pending_keys.borrow_mut().push_back(key);
            }
        }
        Ok(cancelled)
    }

    /*
    This setter transfers parsed macro playback into the Console input owner.
    */
    pub fn start_macro(&self, playback: crate::macros::Playback) {
        *self.playback.borrow_mut() = Some(playback);
    }

    /*
    This notification applies the stored stop-on-notice policy to active playback.
    */
    pub fn macro_notice(&self) {
        if let Some(playback) = self.playback.borrow_mut().as_mut() {
            playback.notice();
        }
    }

    /*
    This modal draws one centered notice and returns the first meaningful key.
    The caller decides which key values close or continue its operation.
    */
    pub fn modal(&self, base: &[String], text: &str) -> io::Result<Key> {
        loop {
            let (width, height) = self.dimensions();
            let mut lines = base.to_vec();
            lines.resize(height, String::new());
            if height != 0 {
                let label = visible(text, width.saturating_sub(4));
                let left = width.saturating_sub(label.chars().count().saturating_add(4)) / 2;
                lines[height / 2] = format!("{}[ {} ]", " ".repeat(left), label);
            }
            self.draw(&lines)?;
            let key = self.key()?;
            if key.code != 0 || key.character != '\0' {
                return Ok(key);
            }
        }
    }

    /*
    This wrapper starts an empty text prompt through the shared seeded prompt path.
    */
    pub fn prompt(&self, base: &[String], label: &str) -> io::Result<Option<String>> {
        self.prompt_seed(base, label, "")
    }

    /*
    This prompt edits one bounded UTF-8 string until Escape cancels or Enter accepts it.
    Only unmodified or Shift text can enter the field, so Alt shortcuts never become prompt text.
    */
    pub fn prompt_seed(
        &self,
        base: &[String],
        label: &str,
        seed: &str,
    ) -> io::Result<Option<String>> {
        let mut value = seed.to_owned();
        let mut replace = !seed.is_empty();
        loop {
            let (width, height) = self.dimensions();
            let mut lines = base.to_vec();
            lines.resize(height, String::new());
            if height != 0 {
                let row = height / 2;
                let label_width = label.chars().count().saturating_add(4);
                let field_width = width.saturating_sub(label_width).max(1);
                let field = visible(&value, field_width.saturating_sub(1));
                lines[row] = format!("  {label}: {field}_");
            }
            self.draw(&lines)?;
            let key = self.key()?;
            match key.code {
                27 => return Ok(None),
                13 => return Ok(Some(value)),
                8 => {
                    value.pop();
                    replace = false;
                }
                _ if key.accepts_text() && value.len() < 1023 => {
                    if replace {
                        value.clear();
                        replace = false;
                    }
                    value.push(key.character);
                }
                _ => {}
            }
        }
    }
}

/*
This destructor restores the cursor, primary screen, and captured Linux terminal settings.
It attempts every cleanup action because Drop cannot return an error.
*/
impl Drop for Console {
    fn drop(&mut self) {
        let mut output = io::stdout().lock();
        let _ = output.write_all(b"\x1b[?25h\x1b[?1049l");
        let _ = output.flush();
        unsafe {
            tcsetattr(STDIN, TCSAFLUSH, &self.old_termios);
        }
    }
}

/*
These unit tests verify the Linux ABI, key conversion, safe display text, and bounded macro delay.
The key tests keep physical and legacy macro modifier behavior explicit.
*/
#[cfg(test)]
mod tests {
    use super::*;

    /*
    This test protects the exact C record layouts used by direct libc calls.
    */
    #[test]
    fn native_layouts_match_x86_64_linux() {
        assert_eq!(std::mem::size_of::<Termios>(), 60);
        let termios = std::mem::MaybeUninit::<Termios>::uninit();
        let base = termios.as_ptr() as usize;
        let chars = unsafe { std::ptr::addr_of!((*termios.as_ptr()).chars) } as usize;
        assert_eq!(chars - base, 17);
        assert_eq!(std::mem::size_of::<WindowSize>(), 8);
        assert_eq!(std::mem::size_of::<PollFd>(), 8);
    }

    /*
    This test covers terminal modifiers, macro scan conversion, Alt commands, and text acceptance.
    */
    #[test]
    fn terminal_sequences_map_to_application_keys() {
        assert_eq!(csi_key(b"18~").unwrap().code, 118);
        assert_eq!(csi_key(b"18;2~").unwrap().control, 16);
        assert_eq!(csi_key(b"18;5~").unwrap().control, 8);
        assert_eq!(csi_key(b"13;2~").unwrap().code, 114);
        assert_eq!(csi_key(b"13;2~").unwrap().control, 16);
        assert_eq!(csi_key(b"1;2R").unwrap().code, 114);
        assert_eq!(csi_key(b"1;2R").unwrap().control, 16);
        assert_eq!(csi_key(b"1;3A").unwrap().control, 2);
        assert_eq!(physical_sequence_key(b"13~"), None);
        assert_eq!(physical_sequence_key(b"1;2R"), None);
        assert_eq!(physical_sequence_key(b"1;3A").unwrap().code, 38);
        let raw_alt_h = alt_key(b'h');
        assert_eq!(
            (raw_alt_h.code, raw_alt_h.character),
            (u16::from(b'H'), 'h')
        );
        for alt in [1, 2] {
            assert_eq!(alt & 12, 0);
            assert!(
                Key {
                    code: u16::from(b'H'),
                    character: 'h',
                    control: alt,
                }
                .is_alt(b'H')
            );
        }
        for control in [4, 8, 12] {
            assert_ne!(control & 12, 0);
        }
        assert!(
            Key {
                code: u16::from(b'H'),
                character: 'h',
                control: 2,
            }
            .is_alt(b'H')
        );
        assert!(
            !Key {
                code: u16::from(b'H'),
                character: 'h',
                control: 10,
            }
            .is_alt(b'H')
        );
        assert!(
            !Key {
                code: u16::from(b'H'),
                character: 'H',
                control: 18,
            }
            .is_alt(b'H')
        );
        assert!(
            Key {
                code: u16::from(b'A'),
                character: 'A',
                control: 16,
            }
            .accepts_text()
        );
        assert!(
            !Key {
                code: u16::from(b'A'),
                character: 'a',
                control: 2,
            }
            .accepts_text()
        );
        assert_eq!(scan_key(0xe04b, 0, 0).unwrap().code, 37);
        assert!(csi_key(b"3~").is_none());
        assert_eq!(key_code(b'p'), u16::from(b'P'));
        assert_eq!(key_code(b'r'), u16::from(b'R'));
        assert_eq!(key_code(b'x'), u16::from(b'X'));
        assert_eq!(key_code(b'{'), 0);
        assert_eq!(
            scan_key(0, u32::from(b'q'), 0).unwrap().code,
            u16::from(b'Q')
        );
        let macro_ctrl_a = scan_key(0, u32::from(b'A'), 8).unwrap();
        assert_eq!((macro_ctrl_a.code, macro_ctrl_a.character), (65, '\u{1}'));
        assert_eq!(scan_key(0, u32::from(b'A'), 0).unwrap().character, 'A');
        assert_eq!(
            (
                scan_key(0, 13, 0).unwrap().code,
                scan_key(0, 13, 0).unwrap().character
            ),
            (13, '\r')
        );
        for (byte, code) in [(1, b'A'), (3, b'C'), (6, b'F'), (19, b'S')] {
            let key = control_key(byte);
            assert_eq!(key.code, u16::from(code));
            assert_eq!(key.character, char::from(byte));
            assert!(key.character.is_control());
        }
    }

    /*
    This test requires safe terminal text and deterministic clipping.
    */
    #[test]
    fn visible_text_blocks_terminal_control_characters() {
        assert_eq!(visible("safe\u{1b}[31m\nname", 20), "safe�[31m�name");
        assert_eq!(visible("abcdef", 3), "abc");
        assert_eq!(visible("a中b", 20), "a\\u{4E2D}b");
        assert_eq!(visible("☺Ç", 2), "☺Ç");
    }

    /*
    This test verifies complete, canceled, and zero-length macro delays.
    */
    #[test]
    fn macro_delay_timing_and_cancellation() {
        let start = Instant::now();
        assert!(wait_delay(40, || Ok(false)).unwrap());
        assert!(start.elapsed() >= Duration::from_millis(40));
        let mut polls = 0;
        assert!(
            !wait_delay(u32::MAX, || {
                polls += 1;
                Ok(polls == 3)
            })
            .unwrap()
        );
        assert_eq!(polls, 3);
        assert!(wait_delay(0, || Ok(false)).unwrap());
        assert!(!wait_delay(0, || Ok(true)).unwrap());
    }
}
