#![no_std]
//! Minimal no-std HTML extraction guest for YuKKi-OS crawler workers.
//!
//! ABI: alloc(len) -> input pointer; process(ptr, len) -> (output_len << 32) | output_ptr.
//! Output is YCR1: magic, input bytes (u32 LE), link count (u16 LE),
//! title length (u16 LE), title bytes, then repeated (u16 LE length, href bytes).

use core::{panic::PanicInfo, slice};

const INPUT_CAP: usize = 1_048_576;
const OUTPUT_CAP: usize = 300_000;
const MAX_LINKS: usize = 128;
const MAX_LINK_BYTES: usize = 2_048;
const MAX_TITLE_BYTES: usize = 256;

static mut INPUT: [u8; INPUT_CAP] = [0; INPUT_CAP];
static mut OUTPUT: [u8; OUTPUT_CAP] = [0; OUTPUT_CAP];

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "C" fn alloc(length: i32) -> i32 {
    if length <= 0 || length as usize > INPUT_CAP {
        return 0;
    }
    core::ptr::addr_of_mut!(INPUT) as *mut u8 as usize as i32
}

#[no_mangle]
pub extern "C" fn process(pointer: i32, length: i32) -> i64 {
    if length < 0 || length as usize > INPUT_CAP {
        return 0;
    }
    let input_base = core::ptr::addr_of!(INPUT) as *const u8 as usize;
    if pointer <= 0 || pointer as usize != input_base {
        return 0;
    }

    unsafe {
        let input = slice::from_raw_parts(pointer as *const u8, length as usize);
        let output_ptr = core::ptr::addr_of_mut!(OUTPUT) as *mut u8;
        let output = slice::from_raw_parts_mut(output_ptr, OUTPUT_CAP);
        if OUTPUT_CAP < 12 || length as usize > u32::MAX as usize {
            return 0;
        }

        output[0..4].copy_from_slice(b"YCR1");
        write_u32(output, 4, length as u32);
        write_u16(output, 8, 0);
        write_u16(output, 10, 0);
        let mut cursor = 12usize;

        if let Some((start, end)) = find_title(input) {
            let (start, end) = trim_ascii(input, start, end);
            let title_len = core::cmp::min(end.saturating_sub(start), MAX_TITLE_BYTES);
            if cursor + title_len <= OUTPUT_CAP {
                output[cursor..cursor + title_len].copy_from_slice(&input[start..start + title_len]);
                write_u16(output, 10, title_len as u16);
                cursor += title_len;
            }
        }

        let mut links = 0usize;
        let mut scan = 0usize;
        while scan + 2 < input.len() && links < MAX_LINKS {
            if input[scan] == b'<' && ascii_lower(input[scan + 1]) == b'a'
                && (input[scan + 2].is_ascii_whitespace() || input[scan + 2] == b'>')
            {
                let tag_end = match find_byte(input, scan + 2, b'>') {
                    Some(end) => end,
                    None => break,
                };
                if let Some((href_start, href_end)) = find_href(input, scan + 2, tag_end) {
                    let (href_start, href_end) = trim_ascii(input, href_start, href_end);
                    let href_len = href_end.saturating_sub(href_start);
                    if href_len > 0 && href_len <= MAX_LINK_BYTES && cursor + 2 + href_len <= OUTPUT_CAP {
                        write_u16(output, cursor, href_len as u16);
                        cursor += 2;
                        output[cursor..cursor + href_len].copy_from_slice(&input[href_start..href_end]);
                        cursor += href_len;
                        links += 1;
                    }
                }
                scan = tag_end + 1;
            } else {
                scan += 1;
            }
        }

        write_u16(output, 8, links as u16);
        let output_ptr = output_ptr as usize as u32;
        let output_len = cursor as u32;
        (((output_len as u64) << 32) | output_ptr as u64) as i64
    }
}

fn ascii_lower(byte: u8) -> u8 {
    if (b'A'..=b'Z').contains(&byte) { byte + 32 } else { byte }
}

fn starts_ascii_case_insensitive(input: &[u8], at: usize, expected: &[u8]) -> bool {
    if at + expected.len() > input.len() { return false; }
    input[at..at + expected.len()].iter().zip(expected.iter())
        .all(|(a, b)| ascii_lower(*a) == ascii_lower(*b))
}

fn find_byte(input: &[u8], start: usize, needle: u8) -> Option<usize> {
    input.get(start..)?.iter().position(|byte| *byte == needle).map(|offset| start + offset)
}

fn find_subsequence(input: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || start >= input.len() { return None; }
    (start..=input.len().saturating_sub(needle.len()))
        .find(|index| starts_ascii_case_insensitive(input, *index, needle))
}

fn trim_ascii(input: &[u8], mut start: usize, mut end: usize) -> (usize, usize) {
    while start < end && input[start].is_ascii_whitespace() { start += 1; }
    while end > start && input[end - 1].is_ascii_whitespace() { end -= 1; }
    (start, end)
}

fn find_title(input: &[u8]) -> Option<(usize, usize)> {
    let open = find_subsequence(input, 0, b"<title")?;
    let content_start = find_byte(input, open, b'>')? + 1;
    let content_end = find_subsequence(input, content_start, b"</title")?;
    Some((content_start, content_end))
}

fn find_href(input: &[u8], mut cursor: usize, end: usize) -> Option<(usize, usize)> {
    while cursor < end {
        while cursor < end && input[cursor].is_ascii_whitespace() { cursor += 1; }
        let name_start = cursor;
        while cursor < end && !input[cursor].is_ascii_whitespace() && input[cursor] != b'=' { cursor += 1; }
        if cursor == name_start { cursor += 1; continue; }
        let name_end = cursor;
        while cursor < end && input[cursor].is_ascii_whitespace() { cursor += 1; }
        if cursor >= end || input[cursor] != b'=' { continue; }
        cursor += 1;
        while cursor < end && input[cursor].is_ascii_whitespace() { cursor += 1; }
        if cursor >= end { break; }
        let quote = if input[cursor] == b'"' || input[cursor] == b'\'' {
            let value = input[cursor];
            cursor += 1;
            Some(value)
        } else { None };
        let value_start = cursor;
        if let Some(quote) = quote {
            while cursor < end && input[cursor] != quote { cursor += 1; }
            let value_end = cursor;
            if cursor < end { cursor += 1; }
            if ascii_name_eq(&input[name_start..name_end], b"href") {
                return Some((value_start, value_end));
            }
        } else {
            while cursor < end && !input[cursor].is_ascii_whitespace() && input[cursor] != b'>' { cursor += 1; }
            let value_end = cursor;
            if ascii_name_eq(&input[name_start..name_end], b"href") {
                return Some((value_start, value_end));
            }
        }
    }
    None
}

fn ascii_name_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right.iter()).all(|(a, b)| ascii_lower(*a) == ascii_lower(*b))
}

fn write_u16(output: &mut [u8], at: usize, value: u16) {
    output[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut [u8], at: usize, value: u32) {
    output[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
