// Copyright (c) 2026, NOFire AI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The filter between a guest's serial console and the host's stdout.
//!
//! The console's output reaches the operator's terminal, and a terminal acts on
//! escape sequences. Some of them change host state: OSC 52 writes the
//! clipboard, OSC 8 draws a hyperlink, OSC 2 sets the window title. Others make
//! the terminal answer on its input side, which hvi reads as console input. An
//! answer still queued when hvi exits is read by the operator's shell.
//! [`ConsoleFilter`] passes only the sequences a console needs.

/// ESC, which starts every escape sequence.
const ESC: u8 = 0x1b;
/// ENQ, which asks the terminal for its answerback message.
const ENQ: u8 = 0x05;
/// BEL, which ends an OSC string.
const BEL: u8 = 0x07;
/// CAN, which cancels a sequence in progress.
const CAN: u8 = 0x18;
/// SUB, which cancels a sequence in progress.
const SUB: u8 = 0x1a;

/// The longest escape sequence the filter holds back. A longer one is dropped.
const MAX_SEQ: usize = 128;

/// The replacement character, UTF-8 encoded, written for malformed UTF-8.
const REPLACEMENT: &[u8] = "\u{fffd}".as_bytes();

/// The DEC private modes (`CSI ? Pm h` and `CSI ? Pm l`) a guest may set.
///
/// Cursor keys, reverse video, origin mode, autowrap, cursor blink and
/// visibility, the alternate screen and bracketed paste. The mouse and focus
/// reporting modes are left out, since they make the terminal send input of its
/// own.
const DEC_MODES: &[u32] = &[1, 5, 6, 7, 12, 25, 47, 1047, 1048, 1049, 2004];

/// Where the filter is in the byte stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Text and C0 controls.
    Ground,
    /// After ESC.
    Escape,
    /// After ESC and one or more intermediate bytes, as in `ESC ( B`.
    EscapeIntermediate,
    /// After `ESC [`, collecting a control sequence.
    Csi,
    /// Inside a control sequence being dropped, up to its final byte.
    CsiIgnore,
    /// Inside a control string, dropped up to its terminator.
    ControlString,
}

/// A byte-at-a-time filter over guest console output.
///
/// The filter passes text, the C0 controls a console uses, and an allowlist of
/// escape sequences for cursor movement, erasing, scrolling, colors and a few
/// display modes. It drops every other escape sequence, every control string
/// (OSC, DCS, SOS, PM and APC), every C1 control and ENQ, and it replaces
/// malformed UTF-8 with U+FFFD. It emits an escape sequence only once the
/// sequence is complete and allowed, so the terminal parses every byte it
/// receives from its ground state.
///
/// The filter keeps its state across calls, so a sequence split across two
/// writes is judged as one.
#[derive(Debug)]
pub struct ConsoleFilter {
    state: State,
    /// The escape sequence held back until its final byte.
    seq: Vec<u8>,
    /// A multi-byte UTF-8 character collected so far.
    utf8: [u8; 4],
    /// How many bytes of `utf8` are filled.
    utf8_len: usize,
    /// How many bytes the character in `utf8` needs.
    utf8_want: usize,
}

impl ConsoleFilter {
    /// Returns a filter in its ground state.
    #[must_use]
    pub fn new() -> Self {
        ConsoleFilter {
            state: State::Ground,
            seq: Vec::with_capacity(MAX_SEQ),
            utf8: [0; 4],
            utf8_len: 0,
            utf8_want: 0,
        }
    }

    /// Filters `input` and appends what may reach the terminal to `out`.
    pub fn filter(&mut self, input: &[u8], out: &mut Vec<u8>) {
        for &b in input {
            self.push(b, out);
        }
    }

    /// Filters one byte.
    fn push(&mut self, b: u8, out: &mut Vec<u8>) {
        if self.utf8_want != 0 {
            if (0x80..=0xbf).contains(&b) {
                self.utf8[self.utf8_len] = b;
                self.utf8_len += 1;
                if self.utf8_len == self.utf8_want {
                    self.finish_utf8(out);
                }
                return;
            }
            // A character cut short by a byte that cannot continue it.
            out.extend_from_slice(REPLACEMENT);
            self.utf8_want = 0;
        }
        match self.state {
            State::Ground => self.ground(b, out),
            State::Escape => self.escape(b, out),
            State::EscapeIntermediate => self.escape_intermediate(b, out),
            State::Csi => self.csi(b, out),
            State::CsiIgnore => self.csi_ignore(b, out),
            State::ControlString => self.control_string(b),
        }
    }

    /// Handles a byte outside any escape sequence.
    fn ground(&mut self, b: u8, out: &mut Vec<u8>) {
        match b {
            ESC => self.start_escape(),
            0x00..=0x1f => execute(b, out),
            0x20..=0x7f => out.push(b),
            _ => self.start_utf8(b, out),
        }
    }

    /// Handles the byte after ESC.
    fn escape(&mut self, b: u8, out: &mut Vec<u8>) {
        match b {
            ESC => self.start_escape(),
            CAN | SUB => self.state = State::Ground,
            0x00..=0x1f => execute(b, out),
            b'[' => {
                self.seq.push(b);
                self.state = State::Csi;
            }
            b']' | b'P' | b'X' | b'^' | b'_' => self.state = State::ControlString,
            0x20..=0x2f => {
                self.seq.push(b);
                self.state = State::EscapeIntermediate;
            }
            // DECSC, DECRC, IND, NEL, RI, DECKPAM and DECKPNM. RIS and HTS are
            // left out: RIS clears the scrollback and the user's settings, and
            // HTS sets a tab stop nothing restores after hvi exits.
            b'7' | b'8' | b'D' | b'E' | b'M' | b'=' | b'>' => {
                out.push(ESC);
                out.push(b);
                self.state = State::Ground;
            }
            0x30..=0x7f => self.state = State::Ground,
            _ => {
                self.state = State::Ground;
                self.ground(b, out);
            }
        }
    }

    /// Handles a byte after ESC and an intermediate byte.
    fn escape_intermediate(&mut self, b: u8, out: &mut Vec<u8>) {
        match b {
            ESC => self.start_escape(),
            CAN | SUB => self.state = State::Ground,
            0x00..=0x1f => execute(b, out),
            0x20..=0x2f => self.hold(b),
            0x30..=0x7e => {
                // A G0 to G3 character set: ASCII, UK or DEC line drawing.
                if self.seq.len() == 2
                    && matches!(self.seq[1], b'(' | b')' | b'*' | b'+')
                    && matches!(b, b'0' | b'A' | b'B')
                {
                    out.extend_from_slice(&self.seq);
                    out.push(b);
                }
                self.state = State::Ground;
            }
            0x7f => {}
            _ => {
                self.state = State::Ground;
                self.ground(b, out);
            }
        }
    }

    /// Handles a byte inside `ESC [`.
    fn csi(&mut self, b: u8, out: &mut Vec<u8>) {
        match b {
            ESC => self.start_escape(),
            CAN | SUB => self.state = State::Ground,
            0x00..=0x1f => execute(b, out),
            0x20..=0x3f => self.hold(b),
            0x40..=0x7e => {
                self.seq.push(b);
                if csi_allowed(&self.seq[2..]) {
                    out.extend_from_slice(&self.seq);
                }
                self.state = State::Ground;
            }
            0x7f => {}
            _ => {
                self.state = State::Ground;
                self.ground(b, out);
            }
        }
    }

    /// Handles a byte of a control sequence being dropped.
    fn csi_ignore(&mut self, b: u8, out: &mut Vec<u8>) {
        match b {
            ESC => self.start_escape(),
            CAN | SUB | 0x40..=0x7e => self.state = State::Ground,
            0x00..=0x1f => execute(b, out),
            0x20..=0x3f | 0x7f => {}
            _ => {
                self.state = State::Ground;
                self.ground(b, out);
            }
        }
    }

    /// Handles a byte of an OSC, DCS, SOS, PM or APC string.
    ///
    /// The string's introducer never reached the terminal, so where the string
    /// ends only decides which later bytes are shown as text.
    fn control_string(&mut self, b: u8) {
        match b {
            ESC => self.start_escape(),
            BEL | CAN | SUB => self.state = State::Ground,
            _ => {}
        }
    }

    /// Starts holding back an escape sequence.
    fn start_escape(&mut self) {
        self.seq.clear();
        self.seq.push(ESC);
        self.state = State::Escape;
    }

    /// Adds `b` to the sequence held back.
    ///
    /// Past [`MAX_SEQ`], a control sequence is dropped up to its final byte. An
    /// escape sequence stops growing, and its final byte then matches no
    /// allowed form.
    fn hold(&mut self, b: u8) {
        if self.seq.len() < MAX_SEQ {
            self.seq.push(b);
        } else if self.state == State::Csi {
            self.state = State::CsiIgnore;
        }
    }

    /// Starts collecting a multi-byte UTF-8 character at lead byte `b`.
    fn start_utf8(&mut self, b: u8, out: &mut Vec<u8>) {
        let want = match b {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            // A continuation byte with no lead, an overlong lead, or a byte
            // outside UTF-8. A terminal in a legacy mode reads 0x80 to 0x9f as
            // C1 controls.
            _ => {
                out.extend_from_slice(REPLACEMENT);
                return;
            }
        };
        self.utf8[0] = b;
        self.utf8_len = 1;
        self.utf8_want = want;
    }

    /// Emits the collected UTF-8 character, a replacement for a malformed one,
    /// or nothing for a C1 control.
    fn finish_utf8(&mut self, out: &mut Vec<u8>) {
        let bytes = &self.utf8[..self.utf8_len];
        self.utf8_want = 0;
        match std::str::from_utf8(bytes) {
            Ok(s) if s.chars().all(|c| !('\u{80}'..='\u{9f}').contains(&c)) => {
                out.extend_from_slice(bytes);
            }
            Ok(_) => {}
            Err(_) => out.extend_from_slice(REPLACEMENT),
        }
    }
}

impl Default for ConsoleFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Emits C0 control `b` unless it is ENQ.
fn execute(b: u8, out: &mut Vec<u8>) {
    if b != ENQ {
        out.push(b);
    }
}

/// Returns whether a control sequence may reach the terminal.
///
/// `body` is everything after `ESC [`: an optional private marker, parameters,
/// intermediate bytes and the final byte.
fn csi_allowed(body: &[u8]) -> bool {
    let Some((&fin, rest)) = body.split_last() else {
        return false;
    };
    let (marker, rest) = match rest.first() {
        Some(&m @ (b'<' | b'=' | b'>' | b'?')) => (Some(m), &rest[1..]),
        _ => (None, rest),
    };
    let split = rest
        .iter()
        .position(|b| (0x20..=0x2f).contains(b))
        .unwrap_or(rest.len());
    let (params, inter) = rest.split_at(split);
    if !params
        .iter()
        .all(|b| b.is_ascii_digit() || *b == b';' || *b == b':')
        || !inter.iter().all(|b| (0x20..=0x2f).contains(b))
    {
        return false;
    }
    match (marker, inter, fin) {
        // Cursor movement, erasing, inserting, deleting, scrolling, moving by
        // tab stops, repeat and SGR. `T` takes one parameter: xterm reads five
        // as the start of mouse highlight tracking. TBC (`g`) is left out,
        // since it clears tab stops nothing restores after hvi exits.
        (
            None,
            [],
            b'@'
            | b'A'..=b'I'
            | b'K'..=b'M'
            | b'P'
            | b'S'
            | b'X'
            | b'Z'
            | b'a'
            | b'b'
            | b'd'..=b'f'
            | b'm'
            | b'r'
            | b's'
            | b'`',
        ) => true,
        (None, [], b'T') => !params.contains(&b';'),
        (None | Some(b'?'), [], b'J') => erase_allowed(params),
        // SCORC takes no parameters. With them, `u` is a keyboard protocol
        // request.
        (None, [], b'u') => params.is_empty(),
        // Insert mode is the one ANSI mode allowed. The others lock the
        // keyboard or change what the terminal sends.
        (None, [], b'h' | b'l') => params == b"4",
        (Some(b'?'), [], b'h' | b'l') => modes_allowed(params),
        (Some(b'?'), [], b'K') => true,
        // DECSCUSR sets the cursor style, DECSTR soft-resets the terminal.
        (None, [b' '], b'q') | (None, [b'!'], b'p') => true,
        _ => false,
    }
}

/// Returns whether an erase in display (`J`) leaves the scrollback alone.
///
/// Parameter 3 erases the saved lines, which hold the user's scrollback from
/// before hvi started.
fn erase_allowed(params: &[u8]) -> bool {
    matches!(params, b"" | b"0" | b"1" | b"2")
}

/// Returns whether every mode in a `;`-separated list is in [`DEC_MODES`].
fn modes_allowed(params: &[u8]) -> bool {
    !params.is_empty()
        && params.split(|b| *b == b';').all(|p| {
            std::str::from_utf8(p)
                .ok()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|m| DEC_MODES.contains(&m))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns what the filter passes of `input`, fed in one call.
    fn run(input: &[u8]) -> Vec<u8> {
        let mut f = ConsoleFilter::new();
        let mut out = Vec::new();
        f.filter(input, &mut out);
        out
    }

    /// Returns what the filter passes of `input`, fed one byte per call as the
    /// PL011 delivers it.
    fn run_bytewise(input: &[u8]) -> Vec<u8> {
        let mut f = ConsoleFilter::new();
        let mut out = Vec::new();
        for b in input {
            f.filter(std::slice::from_ref(b), &mut out);
        }
        out
    }

    #[test]
    fn text_and_console_controls_pass_unchanged() {
        let input = b"Linux version 6.12\r\n\tok\x08\x07 \xce\xb1\xce\xb2 \xe2\x9c\x93";
        assert_eq!(run(input), input);
    }

    #[test]
    fn allowed_sequences_pass_unchanged() {
        for seq in [
            &b"\x1b[0m"[..],
            b"\x1b[1;31m",
            b"\x1b[38:2::255:0:0m",
            b"\x1b[38;5;208;48;2;0;0;0m",
            b"\x1b[H",
            b"\x1b[12;40H",
            b"\x1b[2J",
            b"\x1b[K",
            b"\x1b[?25l",
            b"\x1b[?1049h",
            b"\x1b[?1;2004h",
            b"\x1b[1;24r",
            b"\x1b[2 q",
            b"\x1b[!p",
            b"\x1b7",
            b"\x1b8",
            b"\x1bM",
            b"\x1b[J",
            b"\x1b[?2J",
            b"\x1b[I",
            b"\x1b[2Z",
            b"\x1b(0",
            b"\x1b(B",
        ] {
            assert_eq!(run(seq), seq, "{seq:?}");
            assert_eq!(run_bytewise(seq), seq, "{seq:?}, one byte at a time");
        }
    }

    // Each of these writes host state or makes the terminal write to its input,
    // which hvi forwards to the guest and, after exit, the shell reads.
    #[test]
    fn host_state_and_query_sequences_are_dropped() {
        for seq in [
            &b"\x1b]52;c;aHZpLWNsaXBib2FyZA==\x07"[..],
            b"\x1b]8;;https://example.invalid\x1b\\",
            b"\x1b]2;title\x07",
            b"\x1b]11;?\x07",
            b"\x1b]1337;File=name=eA==:eA==\x07",
            b"\x1bP$qm\x1b\\",
            b"\x1bP+q544e\x1b\\",
            b"\x1b_Gf=24;AAAA\x1b\\",
            b"\x1b^pm\x1b\\",
            b"\x1bXsos\x1b\\",
            b"\x1b[6n",
            b"\x1b[5n",
            b"\x1b[?6n",
            b"\x1b[c",
            b"\x1b[0c",
            b"\x1b[>c",
            b"\x1b[=c",
            b"\x1b[x",
            b"\x1b[21t",
            b"\x1b[14t",
            b"\x1b[8;100;100t",
            b"\x1b[?2004$p",
            b"\x1b[>0q",
            b"\x1b[?u",
            b"\x1b[>1u",
            b"\x1b[?1m",
            b"\x1b[>4;2m",
            b"\x1b[?1;1;0S",
            b"\x1b[?1000h",
            b"\x1b[?1004h",
            b"\x1b[?1006;1000h",
            b"\x1b[?25;1000h",
            b"\x1b[2h",
            b"\x1b[12l",
            b"\x1b[20h",
            b"\x1b[5i",
            b"\x1b[1;2;3;4;5T",
            b"\x1bZ",
            b"\x1bc",
            b"\x1b[3J",
            b"\x1b[?3J",
            b"\x1bH",
            b"\x1b[g",
            b"\x1b[3g",
            b"\x1b F",
            b"\x1b G",
            b"\x1b%G",
            b"\x05",
        ] {
            assert_eq!(run(seq), b"", "{seq:?}");
            assert_eq!(run_bytewise(seq), b"", "{seq:?}, one byte at a time");
        }
    }

    // U+009B and U+009D are CSI and OSC in their C1 form. Bare bytes 0x80 to
    // 0x9f are C1 to a terminal outside UTF-8 mode.
    #[test]
    fn c1_controls_are_dropped_in_either_encoding() {
        assert_eq!(run(b"a\xc2\x9b6nb"), b"a6nb");
        assert_eq!(run(b"a\xc2\x9d52;c;QQ==\x07b"), b"a52;c;QQ==\x07b");
        assert_eq!(run(b"a\x9b6nb"), b"a\xef\xbf\xbd6nb");
        assert_eq!(run(b"\xc2\xa9"), "\u{a9}".as_bytes(), "U+00A9 passes");
    }

    #[test]
    fn malformed_utf8_becomes_the_replacement_character() {
        let r = REPLACEMENT;
        // Overlong ESC, a lone continuation byte, a cut-short character, a
        // surrogate and a byte outside UTF-8.
        assert_eq!(run(b"\xc0\x9b"), [r, r].concat());
        assert_eq!(run(b"\xbf"), r);
        assert_eq!(run(b"\xe2\x9cA"), [r, b"A"].concat());
        assert_eq!(run(b"\xed\xa0\x80"), r);
        assert_eq!(run(b"\xff"), r);
    }

    #[test]
    fn text_after_a_dropped_string_is_kept() {
        assert_eq!(run(b"a\x1b]0;t\x07b"), b"ab");
        assert_eq!(run(b"a\x1b]0;t\x1b\\b"), b"ab");
        assert_eq!(run(b"a\x1b]0;t\x18b"), b"ab");
        assert_eq!(run(b"a\x1b]0;t\x1b[1mb"), b"a\x1b[1mb");
    }

    #[test]
    fn a_control_inside_a_sequence_runs_and_the_sequence_continues() {
        assert_eq!(run(b"\x1b[1\r;31m"), b"\r\x1b[1;31m");
        assert_eq!(run(b"\x1b[6\x05n"), b"");
    }

    #[test]
    fn a_cancelled_or_restarted_sequence_emits_nothing_of_itself() {
        assert_eq!(run(b"\x1b[31\x18m"), b"m");
        assert_eq!(run(b"\x1b[31\x1b[1m"), b"\x1b[1m");
    }

    #[test]
    fn an_overlong_sequence_is_dropped_up_to_its_final_byte() {
        let mut seq = b"\x1b[".to_vec();
        seq.extend_from_slice(&[b'1'; MAX_SEQ]);
        seq.extend_from_slice(b"mok");
        assert_eq!(run(&seq), b"ok");
    }

    // An escape sequence with intermediate bytes ends on 0x30 to 0x7e, a
    // control sequence only on 0x40 to 0x7e, so the `0` here ends it.
    #[test]
    fn an_overlong_escape_sequence_is_dropped_up_to_its_final_byte() {
        let mut seq = vec![ESC];
        seq.extend_from_slice(&[b' '; MAX_SEQ]);
        seq.extend_from_slice(b"0ok");
        assert_eq!(run(&seq), b"ok");
    }

    // A clipboard copy or an inline image runs to several KiB.
    #[test]
    fn a_long_string_is_dropped_whole() {
        let mut input = b"a\x1b]52;c;".to_vec();
        input.resize(input.len() + 8192, b'A');
        input.extend_from_slice(b"\x07ok");
        assert_eq!(run(&input), b"aok");
    }

    #[test]
    fn a_sequence_split_across_writes_is_judged_whole() {
        let mut f = ConsoleFilter::new();
        let mut out = Vec::new();
        f.filter(b"x\x1b[", &mut out);
        f.filter(b"6", &mut out);
        f.filter(b"ny\x1b[3", &mut out);
        f.filter(b"2mz", &mut out);
        assert_eq!(out, b"xy\x1b[32mz");
    }
}
