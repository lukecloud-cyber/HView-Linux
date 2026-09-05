use crate::{console::Console, editor::Editor, editor::Mode, format, inspect, operations};
use std::{fs, io};

pub fn jump(view: &mut Editor, offset: usize, rows: usize) {
    view.goto(offset as u64, rows);
    if view.mode == Mode::Code {
        view.top = view.offset;
    }
}

fn browse(console: &Console, title: &str, items: &[(usize, String)]) -> io::Result<Option<usize>> {
    let mut selected = 0usize;
    let mut column = 0usize;
    loop {
        let (_width, height) = console.dimensions();
        let page = height.saturating_sub(4).max(1);
        let mut lines = vec![String::new(); height];
        if let Some(line) = lines.first_mut() {
            *line = format!(" {title} | {} results", items.len());
        }
        let top = selected / page * page;
        for (index, (offset, text)) in items.iter().enumerate().skip(top).take(page) {
            if let Some(line) = lines.get_mut(index - top + 2) {
                *line = format!(
                    " {} {offset:08X}  {}",
                    if index == selected { '>' } else { ' ' },
                    text.chars().skip(column).collect::<String>()
                );
            }
        }
        if items.is_empty()
            && let Some(line) = lines.get_mut(2)
        {
            *line = " No results.".into();
        }
        if let Some(footer) = lines.last_mut() {
            *footer =
                " Up/Down Select  PgUp/PgDn Page  Left/Right Scroll  Enter Goto  Esc Back".into();
        }
        console.draw(&lines)?;
        match console.key()?.code {
            27 => return Ok(None),
            13 => return Ok(items.get(selected).map(|item| item.0)),
            38 => selected = selected.saturating_sub(1),
            40 => selected = (selected + 1).min(items.len().saturating_sub(1)),
            33 => selected = selected.saturating_sub(page),
            34 => selected = (selected + page).min(items.len().saturating_sub(1)),
            36 => selected = 0,
            35 => selected = items.len().saturating_sub(1),
            37 => column = column.saturating_sub(16),
            39 => {
                column = (column + 16).min(items.iter().map(|item| item.1.len()).max().unwrap_or(0))
            }
            _ => {}
        }
    }
}

pub fn help(console: &Console) -> io::Result<()> {
    let help = [
        " Editor controls",
        " F3 Edit  F9 Save edits  Esc Cancel edits",
        " Ctrl+S Save As: save the buffer to a new file",
        " M or Enter Mode  O Code size  Ctrl+Q Quit",
        " H/J/K/L Move  Ctrl+T Analysis tools",
        " F4 Mode  F5 Goto  F7 Search  F9 Files  F10 Quit",
        " Hex search accepts wildcards: 48 8B ?? A? ?F",
        " Shift+F7 Next match  Ctrl+F7 Previous match",
        " Ctrl+T Analysis tools:",
        "   A  Convert a PE file offset, RVA, or preferred ImageBase VA",
        "   S  Browse ASCII and UTF-16 ASCII strings",
        "   P  Browse PE structures and jump to their bytes",
        "   E  Browse the entropy map",
        "   D  Compare the current buffer with another file",
        "   I  Inspect integers at the cursor",
        "   X  Apply a repeating XOR mask in edit mode",
        "   F  Fill a range with a repeating pattern in edit mode",
        " Tools use the current editor buffer, including unsaved edits.",
        " Address conversion uses the PE preferred ImageBase.",
        " Range offsets and lengths use hexadecimal numbers.",
        " Analysis tools are additions to the reconstruction.",
        " Press Esc or Enter to return.",
    ];
    loop {
        let (_width, height) = console.dimensions();
        let mut lines = vec![String::new(); height];
        for (slot, text) in lines
            .iter_mut()
            .skip(1)
            .take(height.saturating_sub(2))
            .zip(help)
        {
            *slot = text.into();
        }
        console.draw(&lines)?;
        if matches!(console.key()?.code, 27 | 13 | 112) {
            return Ok(());
        }
    }
}

fn number(text: &str) -> Result<usize, String> {
    let text = text.trim();
    usize::from_str_radix(text, 16)
        .map_err(|_| "Enter a hexadecimal offset and length within the address range.".into())
}

fn address_input(text: &str) -> Result<(format::AddressKind, u64), String> {
    let (kind, digits) = text
        .split_once(' ')
        .ok_or("Enter F, R, or V, one space, and a hexadecimal address.")?;
    if kind.len() != 1 || digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("Enter F, R, or V, one space, and a hexadecimal address.".into());
    }
    let kind = match kind {
        "F" => format::AddressKind::File,
        "R" => format::AddressKind::Rva,
        "V" => format::AddressKind::Va,
        _ => return Err("Enter F, R, or V, one space, and a hexadecimal address.".into()),
    };
    let value = u64::from_str_radix(digits, 16)
        .map_err(|_| "The address exceeds the 64-bit address range.".to_string())?;
    Ok((kind, value))
}

fn convert_address(console: &Console, view: &mut Editor, base: &[String]) -> io::Result<()> {
    let Some(input) = console.prompt(base, "PE address: F file, R RVA, or V VA (hex)")? else {
        return Ok(());
    };
    let address = address_input(&input)
        .and_then(|(kind, value)| format::convert_address(&view.data, kind, value));
    let address = match address {
        Ok(address) => address,
        Err(error) => {
            console.modal(base, &error)?;
            return Ok(());
        }
    };
    let file = address
        .file_offset
        .map(|value| format!("{value:08X}"))
        .unwrap_or_else(|| "-".into());
    let rva = address
        .rva
        .map(|value| format!("{value:08X}"))
        .unwrap_or_else(|| "-".into());
    let va = address
        .va
        .map(|value| format!("{value:016X}"))
        .unwrap_or_else(|| "-".into());
    let text = format!("File={file} RVA={rva} VA={va}");
    match address.file_offset {
        Some(offset) if view.data.get(offset).is_some() => {
            if let Some(offset) = browse(
                console,
                "PE address | current buffer, preferred ImageBase",
                &[(offset, text)],
            )? {
                jump(view, offset, console.height().saturating_sub(2));
            }
        }
        Some(_) => {
            console.modal(base, "The converted file offset has no file byte.")?;
        }
        None => {
            console.modal(
                base,
                &format!("{text} | No file bytes exist for this virtual address."),
            )?;
        }
    }
    Ok(())
}

fn change_range(
    console: &Console,
    view: &mut Editor,
    base: &[String],
    xor: bool,
) -> io::Result<()> {
    if !view.editing {
        console.modal(base, "Press F3 to enter edit mode first.")?;
        return Ok(());
    }
    let Some(range) =
        console.prompt_seed(base, "Start Length (hex)", &format!("{:X} 1", view.offset))?
    else {
        return Ok(());
    };
    let fields: Vec<_> = range.split_whitespace().collect();
    let parsed = if fields.len() == 2 {
        number(fields[0]).and_then(|start| number(fields[1]).map(|len| (start, len)))
    } else {
        Err("Enter a start offset and a length.".into())
    };
    let (start, len) = match parsed {
        Ok(range) => range,
        Err(error) => {
            console.modal(base, &error)?;
            return Ok(());
        }
    };
    let Some(mask) = console.prompt(
        base,
        if xor {
            "XOR mask (hex)"
        } else {
            "Fill pattern (hex)"
        },
    )?
    else {
        return Ok(());
    };
    let result = crate::hex_pattern(&mask)
        .and_then(|mask| operations::transform(&mut view.data, start, len, &mask, xor));
    match result {
        Ok(()) => {
            view.dirty = true;
            jump(view, start, console.height().saturating_sub(2));
        }
        Err(error) => {
            console.modal(base, &error)?;
        }
    }
    Ok(())
}

pub fn tools(console: &Console, view: &mut Editor, base: &[String]) -> io::Result<()> {
    let key = loop {
        let (_width, height) = console.dimensions();
        let mut lines = vec![String::new(); height];
        for (line, text) in lines.iter_mut().skip(2).zip([
            " Analysis tools",
            " A  Address: convert a PE file offset, RVA, or preferred ImageBase VA",
            " S  Strings: ASCII and UTF-16 ASCII, minimum 4 characters",
            " P  PE structures: sections, directories, imports, exports, overlay",
            " E  Entropy map: locate compressed or repetitive regions",
            " D  Compare: browse changed ranges against another file",
            " I  Integers: signed and unsigned, little and big endian",
            " X  XOR range: repeat a hexadecimal mask (edit mode)",
            " F  Fill range: repeat a hexadecimal pattern (edit mode)",
            " Esc  Return",
        ]) {
            *line = text.into();
        }
        console.draw(&lines)?;
        let key = console.key()?;
        if key.code != 0 || key.character != '\0' {
            break key;
        }
    };
    let items = match key.character.to_ascii_uppercase() {
        'A' => {
            convert_address(console, view, base)?;
            None
        }
        'S' => {
            // ponytail: Bound result storage. Add streamed results when larger lists are needed.
            let mut items = inspect::strings(&view.data, 4, 10001);
            let title = if items.len() > 10000 {
                items.truncate(10000);
                "Strings | truncated at 10000 results"
            } else {
                "Strings"
            };
            Some((title, items))
        }
        'P' => match format::structures(&view.data, 10001) {
            Ok(mut items) => {
                let title = if items.len() > 10000 {
                    items.truncate(10000);
                    "PE structures | truncated at 10000 results"
                } else {
                    "PE structures"
                };
                Some((title, items))
            }
            Err(error) => {
                console.modal(base, &error)?;
                None
            }
        },
        'E' => {
            let block = 4096usize.max(view.data.len().div_ceil(4096));
            Some((
                "Entropy | bits/byte, not a packer verdict",
                inspect::entropy_map(&view.data, block),
            ))
        }
        'D' => {
            let Some(path) = console.prompt(base, "Compare file")? else {
                return Ok(());
            };
            match fs::read(path.trim().trim_matches('"')) {
                Ok(other) => {
                    let mut items = operations::differences(&view.data, &other, 10001);
                    let title = if items.len() > 10000 {
                        items.truncate(10000);
                        "Compare | buffer -> file | truncated at 10000 ranges"
                    } else {
                        "Compare | buffer -> file"
                    };
                    Some((title, items))
                }
                Err(error) => {
                    console.modal(base, &error.to_string())?;
                    None
                }
            }
        }
        'I' => {
            let rows = inspect::integers(&view.data, view.offset as usize)
                .into_iter()
                .map(|text| (view.offset as usize, text))
                .collect();
            Some(("Integers at cursor", rows))
        }
        'X' | 'F' => {
            change_range(
                console,
                view,
                base,
                key.character.eq_ignore_ascii_case(&'x'),
            )?;
            None
        }
        _ => None,
    };
    if let Some((title, items)) = items
        && let Some(offset) = browse(console, title, &items)?
    {
        jump(view, offset, console.height().saturating_sub(2));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_numbers_require_complete_input() {
        assert_eq!(number("10").unwrap(), 16);
        assert!(number("10junk").is_err());
        assert!(number("").is_err());
        assert!(number("-1").is_err());
    }

    #[test]
    fn address_input_requires_one_complete_hexadecimal_value() {
        use format::AddressKind::{File, Rva, Va};

        assert_eq!(address_input("F 400"), Ok((File, 0x400)));
        assert_eq!(address_input("R 1010"), Ok((Rva, 0x1010)));
        assert_eq!(address_input("V 140001010"), Ok((Va, 0x140001010)));
        for input in [
            "F +400",
            "F -400",
            "F 0x400",
            "F 400 ",
            "F 400 data",
            "F 10000000000000000",
            "A 400",
        ] {
            assert!(address_input(input).is_err(), "accepted {input:?}");
        }
    }
}
