pub const USAGE: &str = "Usage: hview-linux [options] [--] [filemask ...]\n\
  --mode text|hex|code   Select the initial view mode.\n\
  --offset HEX           Start at a file offset.\n\
  --virtual HEX          Start at a PE virtual address.\n\
  --entry-point          Start at the PE entry point.\n\
  --end                  Start at the final byte.\n\
  --config PATH          Read a configuration file.\n\
  --session PATH         Read or write a session file.\n\
  --macro PATH           Play a macro file.\n\
  --recursive            Recurse for following file masks.\n\
  --help                  Show this help.\n\
Legacy /O, /SAV, /INI, /MACRO0, and /s forms remain available.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    ArgumentTooLong,
    InvalidOption,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ArgumentTooLong => "Argument string too long",
            Self::InvalidOption => USAGE,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OffsetTarget {
    File(u64),
    Virtual(u64),
    EntryPoint,
    End,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offset {
    pub mode: u8,
    pub target: OffsetTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMask {
    pub pattern: String,
    pub recursive: bool,
    pub remaining_args: usize,
}

#[cfg(test)]
impl FileMask {
    pub fn split(&self) -> (&str, &str) {
        let split = self.pattern.rfind('\\').or_else(|| self.pattern.rfind(':'));
        self.pattern.split_at(split.map_or(0, |index| index + 1))
    }

    pub fn has_wildcard(&self) -> bool {
        self.split().1.contains(['*', '?'])
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Options {
    pub save_file: Option<String>,
    pub ini_file: Option<String>,
    pub macro_file: Option<String>,
    pub offset: Option<Offset>,
    pub mode: Option<u8>,
    pub file_masks: Vec<FileMask>,
    pub flags: u32,
    pub help: bool,
}

fn legacy_option(arg: &str) -> bool {
    let bytes = arg.as_bytes();
    arg.eq_ignore_ascii_case("/s")
        || arg == "/?"
        || bytes.get(..5).is_some_and(|head| {
            head.eq_ignore_ascii_case(b"/SAV=") || head.eq_ignore_ascii_case(b"/INI=")
        })
        || bytes
            .get(..8)
            .is_some_and(|head| head.eq_ignore_ascii_case(b"/MACRO0="))
        || (bytes.get(1).is_some_and(|byte| byte & 0x5f == b'O')
            && (bytes.len() == 2 || bytes.get(2) == Some(&b'=') || bytes.get(3) == Some(&b'=')))
}

fn option_value<'a>(
    args: &'a [String],
    index: &mut usize,
    argument: &'a str,
    name: &str,
) -> Result<&'a str, CliError> {
    if argument == name {
        *index += 1;
        return args
            .get(*index)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(CliError::InvalidOption);
    }
    argument
        .strip_prefix(name)
        .and_then(|value| value.strip_prefix('='))
        .filter(|value| !value.is_empty())
        .ok_or(CliError::InvalidOption)
}

fn native_mode(value: &str) -> Result<u8, CliError> {
    if value.eq_ignore_ascii_case("text") {
        Ok(1)
    } else if value.eq_ignore_ascii_case("hex") {
        Ok(2)
    } else if value.eq_ignore_ascii_case("code") {
        Ok(3)
    } else {
        Err(CliError::InvalidOption)
    }
}

fn native_number(value: &str) -> Result<u64, CliError> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CliError::InvalidOption);
    }
    u64::from_str_radix(digits, 16).map_err(|_| CliError::InvalidOption)
}

/// Parse arguments after the executable name.
pub fn parse(args: &[String]) -> Result<Options, CliError> {
    let mut options = Options::default();
    let mut recursive = false;
    let mut files_only = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if !files_only && legacy_option(arg) && arg.len() >= 260 {
            return Err(CliError::ArgumentTooLong);
        }
        let bytes = arg.as_bytes();
        if arg == "--" && !files_only {
            files_only = true;
        } else if !files_only && matches!(arg.as_str(), "-h" | "--help") {
            options.help = true;
        } else if !files_only && matches!(arg.as_str(), "-r" | "--recursive") {
            recursive = true;
        } else if !files_only && (arg == "--mode" || arg.starts_with("--mode=")) {
            options.mode = Some(native_mode(option_value(args, &mut index, arg, "--mode")?)?);
        } else if !files_only && (arg == "--offset" || arg.starts_with("--offset=")) {
            let value = native_number(option_value(args, &mut index, arg, "--offset")?)?;
            options.offset = Some(Offset {
                mode: options.mode.unwrap_or(0),
                target: OffsetTarget::File(value),
            });
            options.flags |= 16;
        } else if !files_only && (arg == "--virtual" || arg.starts_with("--virtual=")) {
            let value = native_number(option_value(args, &mut index, arg, "--virtual")?)?;
            options.offset = Some(Offset {
                mode: options.mode.unwrap_or(0),
                target: OffsetTarget::Virtual(value),
            });
            options.flags |= 16;
        } else if !files_only && arg == "--entry-point" {
            options.offset = Some(Offset {
                mode: options.mode.unwrap_or(0),
                target: OffsetTarget::EntryPoint,
            });
            options.flags |= 16;
        } else if !files_only && arg == "--end" {
            options.offset = Some(Offset {
                mode: options.mode.unwrap_or(0),
                target: OffsetTarget::End,
            });
            options.flags |= 16;
        } else if !files_only && (arg == "--config" || arg.starts_with("--config=")) {
            options.ini_file = Some(option_value(args, &mut index, arg, "--config")?.into());
            options.flags |= 2;
        } else if !files_only && (arg == "--session" || arg.starts_with("--session=")) {
            options.save_file = Some(option_value(args, &mut index, arg, "--session")?.into());
            options.flags |= 1;
        } else if !files_only && (arg == "--macro" || arg.starts_with("--macro=")) {
            options.macro_file = Some(option_value(args, &mut index, arg, "--macro")?.into());
            options.flags |= 8;
        } else if !files_only && arg.starts_with('-') {
            return Err(CliError::InvalidOption);
        } else if files_only || !arg.starts_with('/') || !legacy_option(arg) {
            options.file_masks.push(FileMask {
                pattern: arg.clone(),
                recursive,
                remaining_args: args.len() - index,
            });
            options.flags |= 4;
        } else if arg.eq_ignore_ascii_case("/s") {
            recursive = !recursive;
        } else if bytes.len() > 5 && bytes[..5].eq_ignore_ascii_case(b"/SAV=") {
            options.save_file = Some(arg[5..].to_owned());
            options.flags |= 1;
        } else if bytes.len() > 5 && bytes[..5].eq_ignore_ascii_case(b"/INI=") {
            options.ini_file = Some(arg[5..].to_owned());
            options.flags |= 2;
        } else if bytes.len() > 8 && bytes[..8].eq_ignore_ascii_case(b"/MACRO0=") {
            options.macro_file = Some(arg[8..].to_owned());
            options.flags |= 8;
        } else if bytes.get(1).is_some_and(|byte| byte & 0x5f == b'O') {
            let mode = options.offset.as_ref().map_or(0, |offset| offset.mode);
            options.offset = Some(parse_offset(&bytes[2..], mode)?);
            if options
                .offset
                .as_ref()
                .is_some_and(|offset| offset.mode != 0)
            {
                options.mode = options.offset.as_ref().map(|offset| offset.mode);
            }
            options.flags |= 16;
        } else {
            return Err(CliError::InvalidOption);
        }
        index += 1;
    }
    Ok(options)
}

fn parse_offset(mut value: &[u8], mut mode: u8) -> Result<Offset, CliError> {
    if let Some(byte) = value.first() {
        let new_mode = match byte & 0x5f {
            b'T' => 1,
            b'H' => 2,
            b'C' => 3,
            _ => 0,
        };
        if new_mode != 0 {
            mode = new_mode;
            value = &value[1..];
        }
    }
    value = value.strip_prefix(b"=").ok_or(CliError::InvalidOption)?;
    let target = if value.eq_ignore_ascii_case(b"OEP") {
        OffsetTarget::EntryPoint
    } else if value.eq_ignore_ascii_case(b"END") {
        OffsetTarget::End
    } else if let Some(value) = value.strip_prefix(b".") {
        OffsetTarget::Virtual(parse_number(value)?.0)
    } else {
        OffsetTarget::File(parse_number(value)?.0)
    };
    Ok(Offset { mode, target })
}

/// Return the unsigned value and the number of consumed bytes.
pub fn parse_number(input: &[u8]) -> Result<(u64, usize), CliError> {
    if input.first() == Some(&b'"') {
        let mut value = 0u64;
        let mut index = 1;
        loop {
            let byte = *input.get(index).ok_or(CliError::InvalidOption)?;
            if byte == b'"' {
                return Ok((value, index + 1));
            }
            if byte == 0 || value >> 56 != 0 {
                return Err(CliError::InvalidOption);
            }
            let byte = if byte == b'\\' {
                index += 1;
                *input
                    .get(index)
                    .filter(|b| **b != 0)
                    .ok_or(CliError::InvalidOption)?
            } else {
                byte
            };
            value = (value << 8) | u64::from(byte);
            index += 1;
        }
    }
    let prefix = usize::from(
        input
            .get(..2)
            .is_some_and(|s| s.eq_ignore_ascii_case(b"0x")),
    ) * 2;
    let mut scan = prefix;
    if input.get(scan).is_some_and(|b| matches!(b, b'+' | b'-')) {
        scan += 1;
    }
    while input
        .get(scan)
        .is_some_and(|b| b.is_ascii_hexdigit() || *b == b'`')
    {
        scan += 1;
    }
    let suffix = input.get(scan).copied().unwrap_or(0);
    let base = match suffix.to_ascii_uppercase() {
        b'I' => 2,
        b'O' => 8,
        b'T' => 10,
        _ => 16,
    };
    let suffix = matches!(suffix.to_ascii_uppercase(), b'I' | b'O' | b'T' | b'H').then_some(suffix);
    let (mut value, used) = unsigned_prefix(&input[prefix..], base, u64::MAX)?;
    let mut end = prefix + used;
    if base == 16 && input.get(end) == Some(&b'`') {
        if value > u64::from(u32::MAX) {
            return Err(CliError::InvalidOption);
        }
        let (low, used) = unsigned_prefix(&input[end + 1..], 16, u64::from(u32::MAX))?;
        value = (value << 32) | low;
        end += 1 + used;
    }
    if suffix.is_some_and(|suffix| input.get(end) == Some(&suffix)) {
        end += 1;
    }
    Ok((value, end))
}

fn unsigned_prefix(input: &[u8], base: u64, limit: u64) -> Result<(u64, usize), CliError> {
    let mut index = 0;
    while input
        .get(index)
        .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 11 | 12))
    {
        index += 1;
    }
    let negative = input.get(index) == Some(&b'-');
    if input.get(index).is_some_and(|b| matches!(b, b'+' | b'-')) {
        index += 1;
    }
    if base == 16
        && input
            .get(index..index + 2)
            .is_some_and(|s| s.eq_ignore_ascii_case(b"0x"))
    {
        index += 2;
    }
    let start = index;
    let mut value = 0u64;
    while let Some(byte) = input.get(index) {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'z' => u64::from(byte - b'a') + 10,
            b'A'..=b'Z' => u64::from(byte - b'A') + 10,
            _ => break,
        };
        if digit >= base {
            break;
        }
        value = value
            .checked_mul(base)
            .and_then(|v| v.checked_add(digit))
            .filter(|v| *v <= limit)
            .ok_or(CliError::InvalidOption)?;
        index += 1;
    }
    if index == start {
        return Ok((0, 0));
    }
    if negative {
        value = value.wrapping_neg() & limit;
    }
    Ok((value, index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovered_cli_vectors() {
        let args = [
            "/s",
            "*.exe",
            "/s",
            "last.bin",
            "/sav=a",
            "/SAV=b",
            "/ini=c",
            "/macro0=d",
            "/Oh=20t",
            "/O=.100",
        ];
        let options = parse(&args.map(str::to_owned)).unwrap();
        assert_eq!(options.flags, 31);
        assert_eq!(options.save_file.as_deref(), Some("b"));
        assert!(options.file_masks[0].recursive);
        assert!(!options.file_masks[1].recursive);
        assert_eq!(options.file_masks[1].remaining_args, 7);
        assert_eq!(
            options.offset,
            Some(Offset {
                mode: 2,
                target: OffsetTarget::Virtual(256)
            })
        );
        for arg in ["/?", "/SAV=", "/INI=", "/MACRO0=", "/O", "/OQ=0"] {
            assert_eq!(parse(&[arg.to_owned()]), Err(CliError::InvalidOption));
        }
        let paths = parse(&[
            "/tmp/file.bin".into(),
            "/opt/sample.bin".into(),
            "/other/file.bin".into(),
            "--".into(),
            "/s".into(),
        ])
        .unwrap();
        assert_eq!(paths.file_masks[0].pattern, "/tmp/file.bin");
        assert_eq!(paths.file_masks[1].pattern, "/opt/sample.bin");
        assert_eq!(paths.file_masks[2].pattern, "/other/file.bin");
        assert_eq!(paths.file_masks[3].pattern, "/s");
        assert!(parse(&["x".repeat(260)]).is_ok());
        let literal = format!("/SAV={}", "x".repeat(260));
        assert_eq!(
            parse(&["--".into(), literal.clone()]).unwrap().file_masks[0].pattern,
            literal
        );
        assert_eq!(
            parse(&[format!("/SAV={}", "x".repeat(260))]),
            Err(CliError::ArgumentTooLong)
        );
        for arg in ["/O=", "/O=garbage"] {
            assert_eq!(
                parse(&[arg.to_owned()]).unwrap().offset.unwrap().target,
                OffsetTarget::File(0)
            );
        }
        let mask = FileMask {
            pattern: "C:\\a*\\literal".into(),
            recursive: true,
            remaining_args: 1,
        };
        assert!(!mask.has_wildcard());
        assert_eq!(mask.split(), ("C:\\a*\\", "literal"));
    }

    #[test]
    fn native_options_are_explicit_and_strict() {
        let options = parse(
            &[
                "--mode=code",
                "--offset",
                "0x20",
                "--config=config.ini",
                "--session",
                "state.sav",
                "--macro=keys.mac",
                "--recursive",
                "*.bin",
                "--",
                "-literal.bin",
            ]
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(options.mode, Some(3));
        assert_eq!(
            options.offset,
            Some(Offset {
                mode: 3,
                target: OffsetTarget::File(0x20)
            })
        );
        assert_eq!(options.ini_file.as_deref(), Some("config.ini"));
        assert_eq!(options.save_file.as_deref(), Some("state.sav"));
        assert_eq!(options.macro_file.as_deref(), Some("keys.mac"));
        assert!(options.file_masks[0].recursive);
        assert_eq!(options.file_masks[1].pattern, "-literal.bin");

        for arguments in [
            vec!["--mode=bytes"],
            vec!["--offset=10junk"],
            vec!["--virtual"],
            vec!["--unknown"],
            vec!["-literal.bin"],
        ] {
            assert_eq!(
                parse(&arguments.into_iter().map(str::to_owned).collect::<Vec<_>>()),
                Err(CliError::InvalidOption)
            );
        }
        assert!(parse(&["--help".into()]).unwrap().help);
        assert_eq!(
            parse(&["--virtual=10".into()])
                .unwrap()
                .offset
                .unwrap()
                .target,
            OffsetTarget::Virtual(0x10)
        );
    }

    #[test]
    fn recovered_numeric_vectors() {
        for (input, expected, consumed) in [
            ("", 0, 0),
            ("garbage", 0, 0),
            ("12junk", 18, 2),
            ("100t", 100, 4),
            ("101i", 5, 4),
            ("17o", 15, 3),
            ("0x100t", 100, 6),
            (" 100t", 256, 4),
            ("-1", u64::MAX, 2),
            ("1`2", 4294967298, 3),
            ("1`-1", 8589934591, 4),
            ("\"AB\"tail", 16706, 4),
            ("\"A\\B\"", 16706, 5),
            ("FFFFFFFFFFFFFFFF", u64::MAX, 16),
        ] {
            assert_eq!(
                parse_number(input.as_bytes()),
                Ok((expected, consumed)),
                "{input}"
            );
        }
        for input in [
            "10000000000000000",
            "1`100000000",
            "100000000`1",
            "\"123456789\"",
            "\"open",
            "\"x\\",
        ] {
            assert_eq!(
                parse_number(input.as_bytes()),
                Err(CliError::InvalidOption),
                "{input}"
            );
        }
    }
}
