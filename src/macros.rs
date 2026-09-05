const NORMAL_KEYS: &[u8] = include_bytes!("../assets/normal_keys.bin");
const ENHANCED_KEYS: &[u8] = include_bytes!("../assets/enhanced_keys.bin");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacroEvent {
    pub keycode: u32,
    pub modifiers: u8,
}

impl MacroEvent {
    pub fn control_state(self) -> u32 {
        (u32::from(self.modifiers & 1 != 0) * 2)
            | (u32::from(self.modifiers & 2 != 0) * 8)
            | (u32::from(self.modifiers & 4 != 0) * 16)
    }

    pub fn scan_code(self) -> Result<Option<u16>, String> {
        if self.keycode <= 255 {
            return Ok(None);
        }
        if self.keycode & 0xffffff00 != 0xff00 {
            return Err(format!(
                "Macro key code {:08X} is unsupported.",
                self.keycode
            ));
        }
        let column = if self.modifiers & 1 != 0 {
            3
        } else if self.modifiers & 2 != 0 {
            2
        } else if self.modifiers & 4 != 0 {
            1
        } else {
            0
        };
        let code = self.keycode as u8;
        let matches = |pair: &[u8]| matches!(pair[0], 0 | 0xe0) && pair[1] != 0 && pair[1] == code;
        for row in ENHANCED_KEYS.as_chunks::<10>().0 {
            if matches(&row[2 + column * 2..4 + column * 2]) {
                return Ok(Some(u16::from_le_bytes([row[0], row[1]]) | 0xe000));
            }
        }
        for (scan, row) in NORMAL_KEYS.as_chunks::<8>().0.iter().enumerate() {
            if matches(&row[column * 2..column * 2 + 2]) {
                return Ok(Some(scan as u16));
            }
        }
        Err(format!(
            "Macro key code {:08X} is unsupported.",
            self.keycode
        ))
    }
}

#[derive(Debug)]
pub struct Playback {
    events: Vec<MacroEvent>,
    index: usize,
    active: bool,
    pub delay_ms: u32,
    pub repeat: bool,
    pub stop_on_notice: bool,
}

impl Playback {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        // Preserve import of the original fixed-width binary signature.
        const LEGACY: &[u8; 10] = &[72, 105, 101, 119, 77, 97, 99, 114, 111, 0];
        if data.len() < 69
            || (&data[..10] != b"HViewMacro" && &data[..10] != LEGACY)
            || data[14..16] != [0x06, 0x90]
        {
            return Err("Invalid macro file".into());
        }
        let count = usize::from(u16::from_le_bytes([data[16], data[17]]));
        if data.len() < 69 + count * 5 {
            return Err("Invalid macro file".into());
        }
        if count == 0 {
            return Err("Macro 0: is empty".into());
        }
        if count > 1024 {
            return Err("Macro0 files above 1024 records are unsupported.".into());
        }
        let events = data[69..69 + count * 5]
            .as_chunks::<5>()
            .0
            .iter()
            .map(|record| MacroEvent {
                modifiers: record[0],
                keycode: u32::from_le_bytes(record[1..5].try_into().unwrap()),
            })
            .collect();
        Ok(Self {
            events,
            index: 0,
            active: true,
            delay_ms: u32::from_le_bytes(data[18..22].try_into().unwrap()),
            repeat: data[22] & 2 != 0,
            stop_on_notice: data[22] & 1 != 0,
        })
    }

    pub fn active(&self) -> bool {
        self.active && (self.repeat || self.index < self.events.len())
    }

    pub fn next_event(&mut self) -> Option<MacroEvent> {
        if !self.active() {
            self.active = false;
            return None;
        }
        if self.index == self.events.len() {
            self.index = 0;
        }
        let event = self.events[self.index];
        self.index += 1;
        Some(event)
    }

    pub fn cancel(&mut self) {
        self.active = false;
    }

    pub fn notice(&mut self) {
        if self.stop_on_notice {
            self.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(events: &[(u8, u32)], delay: u32, repeat: bool) -> Vec<u8> {
        let mut data = vec![0; 69];
        data[..10].copy_from_slice(b"HViewMacro");
        data[14..16].copy_from_slice(&0x9006u16.to_le_bytes());
        data[16..18].copy_from_slice(&(events.len() as u16).to_le_bytes());
        data[18..22].copy_from_slice(&delay.to_le_bytes());
        data[22] = if repeat { 2 } else { 0 };
        for (modifiers, key) in events {
            data.push(*modifiers);
            data.extend_from_slice(&key.to_le_bytes());
        }
        data
    }

    #[test]
    fn parser_and_playback_vectors() {
        let events = [(0, 0xff3d), (0, u32::from(b'4')), (0, 0xff43), (0, 0xff44)];
        let mut data = fixture(&events, 25, false);
        data.extend_from_slice(b"ignored trailing bytes");
        let mut playback = Playback::parse(&data).unwrap();
        assert_eq!(playback.delay_ms, 25);
        for (modifiers, keycode) in events {
            assert!(playback.active());
            assert_eq!(
                playback.next_event(),
                Some(MacroEvent { keycode, modifiers })
            );
        }
        assert!(!playback.active());
        assert_eq!(playback.next_event(), None);
        let mut playback = Playback::parse(&fixture(&[(7, 0)], u32::MAX, true)).unwrap();
        assert_eq!(playback.delay_ms, u32::MAX);
        assert_eq!(playback.next_event(), playback.next_event());
        assert!(playback.active());
        playback.cancel();
        assert_eq!(playback.next_event(), None);
        let mut notice_data = fixture(&[(0, 65)], 0, true);
        notice_data[22] |= 1;
        let mut playback = Playback::parse(&notice_data).unwrap();
        playback.notice();
        assert!(!playback.active());
        assert!(Playback::parse(&data[..70]).is_err());
        assert!(Playback::parse(&fixture(&[], 0, false)).is_err());
        assert!(Playback::parse(&fixture(&vec![(0, 1); 1025], 0, false)).is_err());
        data[14] = 0;
        assert!(Playback::parse(&data).is_err());
    }

    #[test]
    fn recovered_key_vectors() {
        for (modifiers, keycode, scan) in [
            (0, 0xff3d, 0x3d),
            (4, 0xff56, 0x3d),
            (2, 0xff60, 0x3d),
            (1, 0xff6a, 0x3d),
            (0, 0xff85, 0x57),
            (2, 0xff8a, 0x58),
            (0, 0xff4d, 0xe04d),
        ] {
            assert_eq!(
                MacroEvent { keycode, modifiers }.scan_code(),
                Ok(Some(scan))
            );
        }
        assert_eq!(
            MacroEvent {
                keycode: 65,
                modifiers: 7
            }
            .control_state(),
            26
        );
        assert_eq!(
            MacroEvent {
                keycode: 65,
                modifiers: 0
            }
            .scan_code(),
            Ok(None)
        );
        assert!(
            MacroEvent {
                keycode: 0xfff1,
                modifiers: 0
            }
            .scan_code()
            .is_err()
        );
    }
}
