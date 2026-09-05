mod assembler;
mod checksum;
mod cli;
mod config;
mod console;
mod decoder;
mod editor;
mod files;
mod format;
mod inspect;
mod macros;
mod native;
mod operations;
mod save;
mod workbench;

use console::Console;
use editor::{Editor, Key, Mode};
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

const NORMAL_KEYS: &str = " 1Help   2PutBlk 3Edit   4Mode   5Goto   6DatRef 7Search 8Header 9Files 10Quit  11Hem   12Names ";
const TEXT_KEYS: &str = " 1Help   2Unwrap 3       4Mode   5Goto   6LnFeed 7Search 8Table  9Files 10Quit  11Hem   12      ";
const EDIT_KEYS: &str = " 1Help   2       3Undo   4Byte   5Word   6Dword  7Crypt  8Xor    9Update10Trunc 11      12      ";

fn put(line: &mut [char], column: usize, text: &str) {
    for (slot, ch) in line.iter_mut().skip(column).zip(text.chars()) {
        *slot = ch;
    }
}

fn frame(
    view: &Editor,
    file: &Path,
    console: &Console,
    updated: bool,
    writable: bool,
    metadata: &Result<format::Metadata, String>,
    decoder: &mut Option<decoder::Decoder>,
) -> Vec<String> {
    let (width, height) = console.dimensions();
    let body_rows = height.saturating_sub(2);
    let mut lines = vec![String::new(); height];
    let mut header = vec![' '; width];
    header[0] = '▲';
    put(
        &mut header,
        5,
        &file.file_name().unwrap_or_default().to_string_lossy(),
    );
    put(
        &mut header,
        width.saturating_sub(58),
        if view.editing {
            "↓FWO EDITMODE"
        } else if updated {
            "↓FUO --------"
        } else if writable {
            "↓FWO --------"
        } else {
            "↓FRO --------"
        },
    );
    put(
        &mut header,
        width.saturating_sub(33),
        &format!(
            "{:08X}│HView-Linux {}",
            view.offset,
            env!("CARGO_PKG_VERSION")
        ),
    );
    lines[0] = header.into_iter().collect();
    if view.mode == Mode::Code
        && let Ok((address, _bits)) = code_address(metadata, view.offset)
    {
        let mut code_header: Vec<char> = lines[0].chars().collect();
        put(
            &mut code_header,
            width.saturating_sub(40),
            if view.real_mode {
                "Real16".to_owned()
            } else {
                format!("a{}", view.code_bits)
            }
            .as_str(),
        );
        if address != view.offset {
            put(&mut code_header, width.saturating_sub(31), "PE");
            put(
                &mut code_header,
                width.saturating_sub(28),
                &format!(".{address:08X}"),
            );
        }
        lines[0] = code_header.into_iter().collect();
    }
    let body = if view.mode == Mode::Code {
        code_rows(view, body_rows, metadata, decoder)
    } else {
        view.render_body(width.saturating_sub(1), body_rows)
    };
    for (i, line) in body.iter().enumerate() {
        let bar = if i == 0 {
            '↑'
        } else if i == height.saturating_sub(4) {
            '↓'
        } else if i == height.saturating_sub(3) {
            '▼'
        } else if view.data.is_empty() {
            '░'
        } else {
            '▓'
        };
        if let Some(row) = lines.get_mut(i + 1) {
            *row = format!("{bar}{line}");
        }
    }
    if view.is_text && view.mode == Mode::Text {
        let line_count = view.data[..(view.offset as usize).min(view.data.len())]
            .windows(view.delimiter.len())
            .filter(|pair| *pair == view.delimiter)
            .count();
        let mut header: Vec<char> = lines[0].chars().collect();
        put(
            &mut header,
            width.saturating_sub(38),
            &format!("{line_count:6}"),
        );
        lines[0] = header.into_iter().collect();
    }
    let text_keys = if view.wrap {
        TEXT_KEYS.to_owned()
    } else {
        TEXT_KEYS.replace("2Unwrap", "2Wrap  ")
    };
    let code_edit_keys = EDIT_KEYS.replace("2       ", "2Asm    ");
    let keys = if view.editing && view.mode == Mode::Code {
        &code_edit_keys
    } else if view.editing {
        EDIT_KEYS
    } else if view.mode == Mode::Text {
        &text_keys
    } else {
        NORMAL_KEYS
    };
    if let Some(footer) = lines.last_mut() {
        *footer = format!(
            "{keys}{}",
            "▒".repeat(width.saturating_sub(keys.chars().count()))
        );
    }
    lines
}

fn code_address(
    metadata: &Result<format::Metadata, String>,
    offset: u64,
) -> Result<(u64, u32), String> {
    match metadata {
        Ok(metadata) => metadata.code_address(offset),
        Err(error) => Err(error.clone()),
    }
}

fn decoder_for(
    decoder: &mut Option<decoder::Decoder>,
    bits: u32,
    syntax: decoder::Syntax,
    real_mode: bool,
) -> Result<&decoder::Decoder, String> {
    if decoder.as_ref().is_none_or(|decoder| {
        decoder.bits() != bits || decoder.syntax() != syntax || decoder.real_mode() != real_mode
    }) {
        *decoder = Some(decoder::Decoder::with_mode(bits, syntax, real_mode)?);
    }
    Ok(decoder.as_ref().unwrap())
}

fn decode_at(
    view: &Editor,
    offset: u64,
    metadata: &Result<format::Metadata, String>,
    decoder: &mut Option<decoder::Decoder>,
) -> Result<(u64, decoder::Instruction), String> {
    let (address, _) = code_address(metadata, offset)?;
    let decoded = decoder_for(decoder, view.code_bits, view.syntax, view.real_mode)?
        .decode(&view.data, offset, address);
    let mut instruction = match decoded {
        Ok(instruction) => instruction,
        Err(_) if view.invalid_code_bytes => {
            let byte = *view
                .data
                .get(offset as usize)
                .ok_or("The decoder reached the end of the file.")?;
            decoder::Instruction {
                size: 1,
                hex: format!("{byte:02X}"),
                text: format!("db {byte:02X}"),
            }
        }
        Err(error) => return Err(error),
    };
    if instruction.size == 1
        && let Some(&byte) = view.data.get(offset as usize)
        && ((byte == 0x90 && view.pack_nops) || (byte == 0xCC && view.pack_int3))
    {
        let count = view.data[offset as usize..]
            .iter()
            .take(15)
            .take_while(|&&value| value == byte)
            .count();
        instruction.size = count;
        instruction.hex = format!("{byte:02X}").repeat(count);
    }
    Ok((address, instruction))
}

fn assembly_seed(
    view: &Editor,
    metadata: &Result<format::Metadata, String>,
) -> Result<String, String> {
    let (address, _) = code_address(metadata, view.offset)?;
    decoder::decode(&view.data, view.offset, view.code_bits, address)
        .map(|instruction| instruction.text)
}

fn code_rows(
    view: &Editor,
    rows: usize,
    metadata: &Result<format::Metadata, String>,
    decoder: &mut Option<decoder::Decoder>,
) -> Vec<String> {
    let mut result = Vec::with_capacity(rows);
    let mut offset = view.top;
    while result.len() < rows && offset < view.data.len() as u64 {
        match decode_at(view, offset, metadata, decoder) {
            Ok((address, instruction)) => {
                result.push(format!(
                    "{}{:08X}: {:<31}{}",
                    if address != offset { '.' } else { ' ' },
                    address,
                    instruction
                        .hex
                        .chars()
                        .take(view.opcode_bytes * 2)
                        .collect::<String>(),
                    instruction.text
                ));
                offset += instruction.size as u64;
            }
            Err(error) => {
                result.push(format!(" {offset:08X}: {error}"));
                break;
            }
        }
    }
    result.resize(rows, String::new());
    result
}

fn select_file(console: &Console, mut folder: PathBuf) -> io::Result<Option<PathBuf>> {
    if folder.as_os_str().is_empty() {
        folder = std::env::current_dir()?;
    }
    let mut selected = 0usize;
    loop {
        let mut entries: Vec<_> = fs::read_dir(&folder)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        entries.sort_by_key(|path| {
            (
                !path.is_dir(),
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_ascii_lowercase(),
            )
        });
        if let Some(parent) = folder.parent() {
            entries.insert(0, parent.to_owned());
        }
        selected = selected.min(entries.len().saturating_sub(1));
        let (width, height) = console.dimensions();
        let mut lines = vec![String::new(); height];
        if let Some(line) = lines.get_mut(2) {
            *line = format!("  {}", folder.display());
        }
        for (i, path) in entries
            .iter()
            .skip(selected.saturating_sub(height.saturating_sub(7)))
            .take(height.saturating_sub(6))
            .enumerate()
        {
            if let Some(line) = lines.get_mut(i + 3) {
                *line = format!(
                    "  {} {}{}",
                    if entries.get(selected) == Some(path) {
                        '>'
                    } else {
                        ' '
                    },
                    path.file_name().unwrap_or_default().to_string_lossy(),
                    if path.is_dir() { "/" } else { "" }
                );
            }
        }
        if let Some(footer) = lines.last_mut() {
            *footer = format!(
                " Enter Open   Esc Quit{}",
                " ".repeat(width.saturating_sub(27))
            );
        }
        console.draw(&lines)?;
        match console.key()?.code {
            27 | 121 => return Ok(None),
            38 => selected = selected.saturating_sub(1),
            40 => selected = (selected + 1).min(entries.len().saturating_sub(1)),
            13 => {
                if let Some(path) = entries.get(selected) {
                    if path.is_dir() {
                        folder = path.clone();
                        selected = 0;
                    } else {
                        return Ok(Some(path.clone()));
                    }
                }
            }
            112..=123 => {
                console.modal(&lines, "This file-selector operation is not reconstructed.")?;
            }
            _ => {}
        }
    }
}

fn hex_pattern(text: &str) -> Result<Vec<u8>, String> {
    let value: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if !value.is_ascii() || value.is_empty() || !value.len().is_multiple_of(2) {
        return Err("Enter complete hexadecimal byte pairs.".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| {
            u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16)
                .map_err(|_| "Enter hexadecimal byte pairs.".into())
        })
        .collect()
}

fn new_view(
    data: Vec<u8>,
    mode: Mode,
    offset: u64,
    config: &config::Config,
) -> Result<Editor, String> {
    config.new_view(data, mode, offset)
}

fn startup_mode(options: &cli::Options, config: &config::Config) -> Mode {
    let selected = options
        .mode
        .unwrap_or_else(|| options.offset.as_ref().map_or(0, |offset| offset.mode));
    match selected {
        1 => Mode::Text,
        2 => Mode::Hex,
        3 => Mode::Code,
        _ => match config.start_mode.as_str() {
            "Hex" => Mode::Hex,
            "Code" => Mode::Code,
            _ => Mode::Text,
        },
    }
}

fn restored_path(text: &str) -> Result<PathBuf, String> {
    let path = Path::new(text);
    if path.is_absolute() {
        return Ok(path.into());
    }
    let bytes = text.as_bytes();
    let drive = bytes.get(1) == Some(&b':') && bytes.first().is_some_and(u8::is_ascii_alphabetic);
    if drive || text.contains('\\') {
        return Err(format!(
            "The saved path uses Windows syntax and cannot open on Linux: {text}"
        ));
    }
    Err(format!(
        "The saved path is relative and cannot restore safely: {text}"
    ))
}

enum EditorAction {
    Quit,
    Next,
    Previous,
    Pick(PathBuf),
}

fn open_editor(
    console: &Console,
    mut path: PathBuf,
    options: &cli::Options,
    config: &config::Config,
    saved_view: Option<&config::SavedFile>,
    save_state_enabled: bool,
) -> io::Result<(EditorAction, Option<(PathBuf, Editor)>)> {
    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let key = console.modal(&[], "File not found. Press 'C' for create")?;
            if !key.character.eq_ignore_ascii_case(&'c') {
                return Ok((EditorAction::Quit, None));
            }
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            Vec::new()
        }
        Err(error) => return Err(error),
    };
    let mode = saved_view
        .map(|state| match state.mode {
            2 => Mode::Hex,
            3 => Mode::Code,
            _ => Mode::Text,
        })
        .unwrap_or_else(|| startup_mode(options, config));
    let requested = options
        .offset
        .as_ref()
        .map(|offset| match offset.target {
            cli::OffsetTarget::File(value) => Ok(value),
            cli::OffsetTarget::Virtual(value) => format::virtual_to_file(&data, value),
            cli::OffsetTarget::End => Ok((data.len() as u64).wrapping_sub(1)),
            cli::OffsetTarget::EntryPoint => format::entry_point(&data),
        })
        .transpose();
    let mut initial = match requested {
        Ok(value) => value.unwrap_or(0),
        Err(error) => {
            console.modal(&[], &error)?;
            0
        }
    };
    if options.offset.is_some() && initial >= data.len() as u64 {
        console.modal(&[], "Jump out of file")?;
        initial = 0;
    }
    let mut saved = data.clone();
    let mut view = new_view(data, mode, initial, config).map_err(io::Error::other)?;
    if mode == Mode::Hex {
        view.goto(initial, console.height().saturating_sub(2));
    }
    if mode == Mode::Code {
        view.top = initial;
    }
    if let Some(state) = saved_view {
        if !state.local_offset {
            return Err(io::Error::other(
                "Saved global offset display is not reconstructed.",
            ));
        }
        view.mode = match state.mode {
            2 => Mode::Hex,
            3 => Mode::Code,
            _ => Mode::Text,
        };
        view.offset = state.offset.min(view.data.len() as u64);
        view.top = state.top.min(view.data.len() as u64);
        view.code_bits = state.code_bits;
        view.real_mode = state.real_mode;
        view.wrap = state.wrap;
        view.expand_tabs = state.tab;
        view.text_column = state.text_column;
        view.delimiter = match state.line_feed {
            config::LineFeed::Cr => b"\r",
            config::LineFeed::Lf => b"\n",
            _ => b"\r\n",
        };
    }
    let mut history = Vec::new();
    let mut search: Option<operations::Pattern> = None;
    let mut updated = false;
    let mut writable = false;
    let mut decoder = None;
    loop {
        let metadata = format::Metadata::parse(&view.data);
        let lines = frame(
            &view,
            &path,
            console,
            updated,
            writable,
            &metadata,
            &mut decoder,
        );
        console.draw(&lines)?;
        let key = console.key()?;
        let ctrl = key.control & 12 != 0;
        if ctrl && key.code == 81 && !view.editing {
            return Ok((EditorAction::Quit, Some((path, view))));
        }
        if ctrl && key.code == 83 {
            if let Some(name) = console.prompt(&lines, "Save As (new file)")? {
                let destination = PathBuf::from(name.trim().trim_matches('"'));
                let result = std::path::absolute(&destination).and_then(|destination| {
                    if save_state_enabled {
                        config::SavedState::saved_path(&destination).map_err(io::Error::other)?;
                    }
                    save::save_as(&destination, &view.data)?;
                    Ok(destination)
                });
                match result {
                    Ok(destination) => {
                        path = destination;
                        saved.clone_from(&view.data);
                        view.saved();
                        updated = true;
                    }
                    Err(error) => {
                        let message = if error.kind() == io::ErrorKind::AlreadyExists {
                            format!("The destination already exists. Use a new file name. {error}")
                        } else {
                            error.to_string()
                        };
                        console.modal(&lines, &message)?;
                    }
                }
            }
            continue;
        }
        if ctrl && key.code == 84 {
            workbench::tools(console, &mut view, &lines)?;
            history.clear();
            continue;
        }
        if key.code == 112 {
            workbench::help(console)?;
            continue;
        }
        if key.code == 118 && !view.editing && (ctrl || key.control & 16 != 0) {
            let start = if ctrl {
                (view.offset as usize).checked_sub(1)
            } else {
                (view.offset as usize).checked_add(1)
            };
            match search.as_ref() {
                Some(pattern) => {
                    match start.and_then(|start| pattern.find(&view.data, start, ctrl)) {
                        Some(offset) => {
                            workbench::jump(&mut view, offset, console.height().saturating_sub(2));
                            history.clear();
                        }
                        None => {
                            console.modal(&lines, "Not found")?;
                        }
                    }
                }
                None => {
                    console.modal(&lines, "Press F7 to enter a search pattern first.")?;
                }
            }
            continue;
        }
        if ctrl && !view.editing {
            if key.code == 123 {
                return Ok((EditorAction::Next, Some((path, view))));
            }
            if key.code == 122 {
                return Ok((EditorAction::Previous, Some((path, view))));
            }
        }
        let navigation = match key.code {
            37 => Some(Key::Left),
            39 => Some(Key::Right),
            38 => Some(Key::Up),
            40 => Some(Key::Down),
            36 => Some(if ctrl { Key::FileStart } else { Key::Home }),
            35 => Some(if ctrl { Key::FileEnd } else { Key::End }),
            33 => Some(Key::PageUp),
            34 => Some(Key::PageDown),
            _ if !ctrl && !view.editing => match key.character.to_ascii_lowercase() {
                'h' => Some(Key::Left),
                'l' => Some(Key::Right),
                'k' => Some(Key::Up),
                'j' => Some(Key::Down),
                _ => None,
            },
            _ => None,
        };
        if let Some(key) = navigation {
            if view.mode == Mode::Code {
                let count = if matches!(key, Key::PageDown | Key::PageUp) {
                    console.height().saturating_sub(2)
                } else {
                    1
                };
                match key {
                    Key::Down | Key::Right | Key::PageDown => {
                        for _ in 0..count {
                            match decode_at(&view, view.offset, &metadata, &mut decoder) {
                                Ok((_address, instruction)) => {
                                    history.push(view.offset);
                                    view.offset = (view.offset + instruction.size as u64)
                                        .min(view.data.len() as u64);
                                    view.top = view.offset;
                                }
                                Err(error) => {
                                    console.modal(&lines, &error)?;
                                    break;
                                }
                            }
                        }
                    }
                    Key::Up | Key::Left | Key::PageUp => {
                        for _ in 0..count {
                            if let Some(offset) = history.pop() {
                                view.offset = offset;
                                view.top = offset;
                            }
                        }
                    }
                    Key::Home | Key::FileStart => {
                        view.offset = 0;
                        view.top = 0;
                        history.clear();
                    }
                    _ => {
                        console.modal(
                            &lines,
                            "This code-navigation operation is not reconstructed.",
                        )?;
                    }
                }
            } else {
                view.navigate(
                    key,
                    console.height().saturating_sub(2),
                    console.width().saturating_sub(1),
                );
            }
            continue;
        }
        if view.editing && view.mode == Mode::Hex && key.character.is_ascii_hexdigit() {
            if let Err(error) = view.hex_digit(key.character) {
                console.modal(&lines, &error)?;
            }
            continue;
        }
        match key.code {
            13 | 113 if view.editing && view.mode == Mode::Code => loop {
                let metadata = format::Metadata::parse(&view.data);
                let lines = frame(
                    &view,
                    &path,
                    console,
                    updated,
                    writable,
                    &metadata,
                    &mut decoder,
                );
                let seed = assembly_seed(&view, &metadata).unwrap_or_default();
                let Some(text) = console.prompt_seed(&lines, "Assembler", &seed)? else {
                    break;
                };
                let assembled = code_address(&metadata, view.offset)
                    .and_then(|(address, _)| assembler::assemble(&text, view.code_bits, address));
                match assembled {
                    Ok(bytes) => {
                        let start = view.offset as usize;
                        let end = start.checked_add(bytes.len()).ok_or_else(|| {
                            io::Error::other("The instruction exceeds the address range.")
                        })?;
                        if end > view.data.len() {
                            view.data.resize(end, 0);
                        }
                        view.data[start..end].copy_from_slice(&bytes);
                        view.dirty = true;
                        view.offset = end as u64;
                    }
                    Err(error) => {
                        console.modal(&lines, &error)?;
                    }
                }
            },
            27 if view.editing => view.cancel_edit(),
            27 | 121 if !view.editing => break,
            114 => {
                if view.editing {
                    view.undo_current_byte();
                } else if let Err(error) = view.toggle_edit() {
                    console.modal(&lines, &error)?;
                } else {
                    writable = true;
                }
            }
            120 if view.editing => match save::replace(&path, &saved, &view.data) {
                Ok(_) => {
                    saved.clone_from(&view.data);
                    view.saved();
                    updated = true;
                }
                Err(error) => {
                    console.modal(&lines, &error.to_string())?;
                }
            },
            code if !view.editing
                && (code == 115 || code == 13 || key.character.eq_ignore_ascii_case(&'m')) =>
            {
                if let Some(mode) = console.prompt(&lines, "Mode: T Text, H Hex, C Code")? {
                    match mode.to_ascii_uppercase().as_str() {
                        "T" | "1" => {
                            view = new_view(view.data, Mode::Text, view.offset, config)
                                .map_err(io::Error::other)?
                        }
                        "H" | "2" => {
                            view = new_view(view.data, Mode::Hex, view.offset, config)
                                .map_err(io::Error::other)?;
                            view.goto(view.offset, console.height().saturating_sub(2));
                        }
                        "C" | "3" => {
                            view.mode = Mode::Code;
                            view.top = view.offset;
                            history.clear();
                        }
                        _ => {}
                    }
                }
            }
            _ if !view.editing
                && view.mode == Mode::Code
                && key.character.eq_ignore_ascii_case(&'o') =>
            {
                if view.real_mode {
                    view.real_mode = false;
                    view.code_bits = 16;
                } else {
                    match view.code_bits {
                        16 => view.code_bits = 32,
                        32 => view.code_bits = 64,
                        _ => {
                            view.code_bits = 16;
                            view.real_mode = true;
                        }
                    }
                }
                decoder = None;
                history.clear();
            }
            116 if !view.editing => {
                if let Some(value) = console.prompt(&lines, "Goto")? {
                    match cli::parse_number(value.as_bytes()) {
                        Ok((offset, _)) if offset < view.data.len() as u64 => {
                            view.goto(offset, console.height().saturating_sub(2));
                            if view.mode == Mode::Code {
                                view.top = offset;
                            }
                        }
                        _ => {
                            console.modal(&lines, "Jump out of file")?;
                        }
                    }
                }
            }
            118 if !view.editing => {
                if let Some(value) = console.prompt(
                    &lines,
                    if view.mode == Mode::Hex {
                        "Hex"
                    } else {
                        "ASCII"
                    },
                )? {
                    let pattern = if view.mode == Mode::Hex {
                        operations::parse_pattern(&value)
                    } else {
                        operations::Pattern::exact(value.into_bytes())
                    };
                    match pattern {
                        Ok(pattern) => {
                            let found = pattern.find(&view.data, view.offset as usize, false);
                            search = Some(pattern);
                            match found {
                                Some(offset) => {
                                    workbench::jump(
                                        &mut view,
                                        offset,
                                        console.height().saturating_sub(2),
                                    );
                                    history.clear();
                                }
                                None => {
                                    console.macro_notice();
                                    console.modal(&lines, "Not found")?;
                                }
                            }
                        }
                        Err(error) => {
                            console.modal(&lines, &error)?;
                        }
                    }
                }
            }
            113 if view.mode == Mode::Text => view.wrap = !view.wrap,
            117 if view.mode == Mode::Text => {
                console.modal(&lines, "Alternate line-feed handling is not reconstructed.")?;
            }
            120 if !view.editing => {
                if let Some(next) =
                    select_file(console, path.parent().unwrap_or(Path::new(".")).to_owned())?
                {
                    return Ok((EditorAction::Pick(next), Some((path, view))));
                }
            }
            112..=123 => {
                console.modal(&lines, "This operation is not reconstructed.")?;
            }
            _ => {}
        }
    }
    Ok((EditorAction::Quit, Some((path, view))))
}

fn run() -> io::Result<()> {
    let raw_args: Vec<_> = std::env::args_os().skip(1).collect();
    if raw_args == [std::ffi::OsString::from("--self-test")] {
        for (bits, text, bytes) in [
            (16, "ret", &[0xc3][..]),
            (32, "nop", &[0x90][..]),
            (64, "mov rax,rbx", &[0x48, 0x89, 0xd8][..]),
        ] {
            let output = assembler::assemble(text, bits, 0x1000).map_err(io::Error::other)?;
            let instruction = decoder::decode(bytes, 0, bits, 0x1000).map_err(io::Error::other)?;
            if output != bytes || instruction.size != bytes.len() {
                return Err(io::Error::other("The native instruction check failed."));
            }
        }
        println!("Native self-test passed.");
        return Ok(());
    }
    let args: Vec<String> = raw_args
        .into_iter()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| io::Error::other("A command argument is not valid UTF-8."))
        })
        .collect::<io::Result<_>>()?;
    let options = cli::parse(&args).map_err(|error| io::Error::other(error.to_string()))?;
    if options.help {
        println!("{}", cli::USAGE);
        return Ok(());
    }
    if console::redirected() {
        return Err(io::Error::other(
            "HView-Linux needs an interactive terminal.",
        ));
    }
    let console = Console::new()?;
    let executable = std::env::current_exe()?;
    let portable = std::env::var_os("HVIEW_PORTABLE").as_deref() == Some(std::ffi::OsStr::new("1"));
    let ini = options.ini_file.as_ref().map(PathBuf::from).or_else(|| {
        config::configuration_paths(
            &executable,
            portable,
            std::env::var_os("XDG_CONFIG_HOME").as_deref(),
            std::env::var_os("HOME").as_deref(),
        )
        .into_iter()
        .find(|path| path.is_file())
    });
    let config = if let Some(path) = ini {
        config::load(&path).map_err(io::Error::other)?
    } else {
        config::Config::default()
    };
    let save_path = options
        .save_file
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(&config.savefile));
    let session_enabled = config.savefile_at_exit || options.save_file.is_some();
    let saved_bytes = if session_enabled {
        match fs::read(&save_path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    let mut saved_state =
        if options.file_masks.is_empty() && session_enabled && saved_bytes.is_some() {
            Some(config::parse_saved(saved_bytes.as_deref().unwrap()).map_err(io::Error::other)?)
        } else {
            None
        };
    let mut playback = options
        .macro_file
        .as_ref()
        .map(|path| {
            fs::read(path)
                .map_err(|error| error.to_string())
                .and_then(|bytes| macros::Playback::parse(&bytes))
        })
        .transpose()
        .map_err(io::Error::other)?;
    let mut paths = if let Some(state) = &saved_state {
        state
            .files
            .iter()
            .map(|file| {
                let path = restored_path(&file.path).map_err(io::Error::other)?;
                if !path.is_file() {
                    return Err(io::Error::other(format!(
                        "The saved file does not exist on Linux: {}",
                        path.display()
                    )));
                }
                Ok(path)
            })
            .collect::<io::Result<Vec<_>>>()?
    } else if options.file_masks.is_empty() {
        match select_file(&console, std::env::current_dir()?)? {
            Some(path) => vec![path],
            None => return Ok(()),
        }
    } else {
        files::expand(&options.file_masks).map_err(io::Error::other)?
    };
    if paths.is_empty() {
        let (width, height) = console.dimensions();
        let mut lines = vec![String::new(); height];
        if let Some(line) = lines.first_mut() {
            *line = format!("     {}", std::env::current_dir()?.display());
        }
        let keys = " 1       2       3       4       5       6       7       8       9      10      11      12      ";
        if let Some(footer) = lines.last_mut() {
            *footer = format!(
                "{keys}{}",
                "▒".repeat(width.saturating_sub(keys.chars().count()))
            );
        }
        console.modal(&lines, "Couldn't open file")?;
        return Ok(());
    }
    let mut index = saved_state.as_ref().map_or(0, |state| state.active_index);
    if let Some(playback) = playback.take() {
        console.start_macro(playback);
    }
    loop {
        let (action, view) = open_editor(
            &console,
            paths[index].clone(),
            &options,
            &config,
            saved_state
                .as_ref()
                .and_then(|state| state.files.get(index)),
            session_enabled,
        )?;
        if let Some((path, view)) = view {
            paths[index] = path;
            if let Some(state) = &mut saved_state {
                let saved_path =
                    config::SavedState::saved_path(&paths[index]).map_err(io::Error::other)?;
                if index == state.files.len() {
                    state
                        .add_file(&saved_path, &view, &config)
                        .map_err(io::Error::other)?;
                } else if state.files[index].path != saved_path {
                    state
                        .update_path(index, &saved_path)
                        .map_err(io::Error::other)?;
                }
                state.update_view(index, &view).map_err(io::Error::other)?;
            } else if session_enabled {
                saved_state = Some(
                    config::SavedState::new_files(
                        &paths,
                        index,
                        &view,
                        &config,
                        startup_mode(&options, &config),
                        options.offset.as_ref(),
                    )
                    .map_err(io::Error::other)?,
                );
            }
        }
        match action {
            EditorAction::Quit => break,
            EditorAction::Next => index = (index + 1) % paths.len(),
            EditorAction::Previous => index = (index + paths.len() - 1) % paths.len(),
            EditorAction::Pick(path) => {
                let canonical = path.canonicalize().ok();
                if let Some(found) = paths.iter().position(|p| {
                    *p == path
                        || canonical
                            .as_ref()
                            .is_some_and(|target| p.canonicalize().ok().as_ref() == Some(target))
                }) {
                    index = found;
                } else if session_enabled && paths.len() >= 24 {
                    console.modal(&[], "A save state supports no more than 24 files.")?;
                } else {
                    if session_enabled && let Err(error) = config::SavedState::saved_path(&path) {
                        console.modal(&[], &error)?;
                        continue;
                    }
                    paths.push(path);
                    index = paths.len() - 1;
                }
            }
        }
    }
    if session_enabled && let Some(state) = saved_state {
        let bytes = config::encode_saved(&state.payload).map_err(io::Error::other)?;
        if let Some(before) = saved_bytes {
            save::replace(&save_path, &before, &bytes)?;
        } else {
            save::save_as(&save_path, &bytes)?;
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{}", console::safe_text(&error.to_string()));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Run the redraw preparation benchmark manually."]
    fn d01_redraw_preparation_benchmark() {
        const ROWS: usize = 28;
        const WARMUPS: usize = 5;
        const BATCHES: usize = 10;
        const PREPARATIONS_PER_BATCH: usize = 5;

        fn measure(label: &str, view: &Editor) {
            let mut decoder = None;
            for _ in 0..WARMUPS {
                let metadata = format::Metadata::parse(std::hint::black_box(&view.data));
                std::hint::black_box(code_rows(
                    std::hint::black_box(view),
                    ROWS,
                    &metadata,
                    &mut decoder,
                ));
            }

            let mut samples = Vec::with_capacity(BATCHES);
            for _ in 0..BATCHES {
                let start = std::time::Instant::now();
                for _ in 0..PREPARATIONS_PER_BATCH {
                    let metadata = format::Metadata::parse(std::hint::black_box(&view.data));
                    std::hint::black_box(code_rows(
                        std::hint::black_box(view),
                        ROWS,
                        &metadata,
                        &mut decoder,
                    ));
                }
                samples.push(start.elapsed().as_nanos() / PREPARATIONS_PER_BATCH as u128);
            }
            samples.sort_unstable();
            let median = (samples[BATCHES / 2 - 1] + samples[BATCHES / 2]) / 2;
            let p95 = samples[(BATCHES * 95).div_ceil(100) - 1];
            println!(
                "D01 {label}: rows={ROWS} warmups={WARMUPS} batches={BATCHES} preparations_per_batch={PREPARATIONS_PER_BATCH} median_ns={median} p95_ns={p95}"
            );
        }

        let raw = [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x90].repeat(32);
        let mut raw_view = Editor::new(raw, Mode::Code, 0);
        raw_view.code_bits = 32;
        raw_view.pack_nops = false;
        raw_view.pack_int3 = false;

        let pe_data = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/windows-capstone-5.0.9.dll"),
        )
        .expect("Cannot read the PE benchmark workload.");
        let entry = format::entry_point(&pe_data).expect("Cannot read the PE entry point.");
        let bits = format::code_address(&pe_data, entry)
            .expect("Cannot read the PE code size.")
            .1;
        let mut pe_view = Editor::new(pe_data, Mode::Code, entry);
        pe_view.top = entry;
        pe_view.code_bits = bits;
        pe_view.pack_nops = false;
        pe_view.pack_int3 = false;

        measure("raw-x86", &raw_view);
        measure("capstone-pe-entry", &pe_view);
    }

    #[test]
    fn decoder_for_reuses_and_replaces_decoder() {
        let mut decoder = None;
        assert_eq!(
            decoder_for(&mut decoder, 32, decoder::Syntax::Intel, false)
                .unwrap()
                .bits(),
            32
        );
        assert_eq!(
            decoder_for(&mut decoder, 32, decoder::Syntax::Att, false)
                .unwrap()
                .syntax(),
            decoder::Syntax::Att
        );
        assert_eq!(
            decoder_for(&mut decoder, 16, decoder::Syntax::Intel, false)
                .unwrap()
                .bits(),
            16
        );
        assert_eq!(
            decoder_for(&mut decoder, 64, decoder::Syntax::Intel, false)
                .unwrap()
                .bits(),
            64
        );
        assert!(decoder_for(&mut decoder, 8, decoder::Syntax::Intel, false).is_err());
        assert!(
            decoder_for(&mut decoder, 16, decoder::Syntax::Intel, true)
                .unwrap()
                .real_mode()
        );
    }

    #[test]
    fn search_input_and_native_layout() {
        assert_eq!(hex_pattern("21 22").unwrap(), [0x21, 0x22]);
        assert!(hex_pattern("2").is_err());
        assert!(hex_pattern("xx").is_err());
    }

    #[test]
    fn assembly_seed_stays_intel_with_att_display() {
        let mut view = Editor::new(vec![0x89, 0xd8], Mode::Code, 0);
        view.code_bits = 32;
        view.syntax = decoder::Syntax::Att;
        let seed = assembly_seed(&view, &format::Metadata::parse(&view.data)).unwrap();
        assert!(seed.contains("eax, ebx"));
        assert!(!seed.contains('%'));
    }

    #[test]
    fn invalid_byte_fallback_is_explicit() {
        let metadata = format::Metadata::parse(&[0x0f]);
        let mut decoder = None;
        let mut view = Editor::new(vec![0x0f], Mode::Code, 0);
        assert!(decode_at(&view, 0, &metadata, &mut decoder).is_err());
        view.invalid_code_bytes = true;
        let (_, instruction) = decode_at(&view, 0, &metadata, &mut decoder).unwrap();
        assert_eq!((instruction.size, instruction.text.as_str()), (1, "db 0F"));
    }

    #[test]
    fn restored_paths_reject_windows_syntax() {
        assert_eq!(
            restored_path("/tmp/file.bin").unwrap(),
            Path::new("/tmp/file.bin")
        );
        assert_eq!(
            restored_path("/tmp/name\\part.bin").unwrap(),
            Path::new("/tmp/name\\part.bin")
        );
        assert!(restored_path("C:\\file.bin").is_err());
        assert!(restored_path("\\\\server\\file.bin").is_err());
        assert!(restored_path("folder\\file.bin").is_err());
        assert!(restored_path("relative.bin").is_err());
    }

    #[test]
    fn native_backslash_path_roundtrips_through_a_session() {
        let folder = std::env::temp_dir().join(format!(
            "hview-backslash-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&folder).unwrap();
        let path = folder.join("name\\part.bin");
        std::fs::write(&path, b"data").unwrap();
        let view = Editor::new(b"data".to_vec(), Mode::Hex, 0);
        let state = config::SavedState::new_files(
            std::slice::from_ref(&path),
            0,
            &view,
            &config::Config::default(),
            Mode::Hex,
            None,
        )
        .unwrap();
        let parsed = config::parse_saved(&config::encode_saved(&state.payload).unwrap()).unwrap();
        assert_eq!(restored_path(&parsed.files[0].path).unwrap(), path);
        std::fs::remove_dir_all(folder).unwrap();
    }
}
