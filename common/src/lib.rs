pub mod errors;
pub mod file_utils;
pub mod pattern_matcher;
pub mod request_parser;
pub mod resp_builder_v2;
pub mod resp_response_parser_v2;
pub mod stopwatch;
pub mod ticker;

pub use errors::{CommonError, ParserError};
pub use pattern_matcher::*;
pub use request_parser::*;
pub use resp_builder_v2::RespBuilderV2;
pub use resp_response_parser_v2::{RespResponseParserV2, ResponseParseResult, ValkeyObject};
pub use stopwatch::*;

use bytes::BytesMut;
use rand::prelude::*;
use std::collections::VecDeque;
use std::str::FromStr;

pub struct StringUtils {}
pub struct BytesMutUtils {}
pub struct TimeUtils {}

#[derive(Copy, Clone, PartialEq, Eq)]
enum InlineState {
    Normal,
    DoubleQuotes,
    SingleQuotes,
    Escape,
}

const UNCLOSED_DOUBLE_QUOTES: &str = "unclosed double quotes";
const UNCLOSED_SINGLE_QUOTES: &str = "unclosed single quotes";
const TRAILING_ESCAPE_CHAR: &str = "trailing escape character";

impl StringUtils {
    /// Find `what` in `buffer`
    pub fn find_subsequence(buffer: &[u8], what: &[u8]) -> Option<usize> {
        buffer.windows(what.len()).position(|window| window == what)
    }

    /// Split `buffer` by white-space
    pub fn split(buffer: &mut BytesMut) -> Result<Vec<BytesMut>, ParserError> {
        let mut word = BytesMut::with_capacity(1024);
        let mut words = Vec::<BytesMut>::new();
        let mut state = InlineState::Normal;
        let mut prev_state = InlineState::Normal;

        for ch in buffer.iter() {
            match state {
                InlineState::Escape => match ch {
                    b'n' => {
                        word.extend([b'\n']);
                        state = prev_state;
                    }
                    b'r' => {
                        word.extend([b'\r']);
                        state = prev_state;
                    }
                    b't' => {
                        word.extend([b'\t']);
                        state = prev_state;
                    }
                    _ => {
                        word.extend([*ch]);
                        state = prev_state;
                    }
                },
                InlineState::Normal => match ch {
                    b'"' => {
                        if !word.is_empty() {
                            words.push(word.clone());
                            word.clear();
                        }
                        state = InlineState::DoubleQuotes;
                    }
                    b'\'' => {
                        if !word.is_empty() {
                            words.push(word.clone());
                            word.clear();
                        }
                        state = InlineState::SingleQuotes;
                    }
                    b' ' | b'\t' => {
                        if !word.is_empty() {
                            words.push(word.clone());
                            word.clear();
                        }
                    }
                    b'\\' => {
                        prev_state = InlineState::Normal;
                        state = InlineState::Escape;
                    }
                    _ => {
                        word.extend([ch]);
                    }
                },
                InlineState::DoubleQuotes => match ch {
                    b'"' => {
                        if !word.is_empty() {
                            words.push(word.clone());
                            word.clear();
                        }
                        state = InlineState::Normal;
                    }
                    b'\\' => {
                        prev_state = InlineState::DoubleQuotes;
                        state = InlineState::Escape;
                    }
                    _ => {
                        word.extend([ch]);
                    }
                },
                InlineState::SingleQuotes => match ch {
                    b'\'' => {
                        if !word.is_empty() {
                            words.push(word.clone());
                            word.clear();
                        }
                        state = InlineState::Normal;
                    }
                    b'\\' => {
                        prev_state = InlineState::SingleQuotes;
                        state = InlineState::Escape;
                    }
                    _ => {
                        word.extend([ch]);
                    }
                },
            }
        }

        match state {
            InlineState::DoubleQuotes => {
                // parsing ended with broken string or bad escaping
                Err(ParserError::InvalidInput(
                    UNCLOSED_DOUBLE_QUOTES.to_string(),
                ))
            }
            InlineState::Normal => {
                // add the remainder
                if !word.is_empty() {
                    words.push(word.clone());
                    word.clear();
                }
                Ok(words)
            }
            InlineState::SingleQuotes => Err(ParserError::InvalidInput(
                UNCLOSED_SINGLE_QUOTES.to_string(),
            )),
            InlineState::Escape => Err(ParserError::InvalidInput(TRAILING_ESCAPE_CHAR.to_string())),
        }
    }

    /// Convert `s` into `usize`
    pub fn parse_str_to_number<F: FromStr>(s: &str) -> Result<F, CommonError> {
        let Ok(num) = FromStr::from_str(s) else {
            return Err(CommonError::InvalidArgument(format!(
                "failed to parse string `{}` to number",
                s
            )));
        };
        Ok(num)
    }
}

impl TimeUtils {
    /// Return milliseconds elapsed since EPOCH
    pub fn epoch_ms() -> Result<u64, CommonError> {
        let Ok(timestamp_ms) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        else {
            return Err(CommonError::OtherError(
                "failed to retrieve std::time::UNIX_EPOCH".to_string(),
            ));
        };
        Ok(timestamp_ms.as_millis().try_into().unwrap_or(u64::MAX))
    }

    /// Return microseconds elapsed since EPOCH
    pub fn epoch_micros() -> Result<u64, CommonError> {
        let Ok(timestamp_ms) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        else {
            return Err(CommonError::OtherError(
                "failed to retrieve std::time::UNIX_EPOCH".to_string(),
            ));
        };
        Ok(timestamp_ms.as_micros().try_into().unwrap_or(u64::MAX))
    }

    /// Return seconds elapsed since EPOCH
    pub fn epoch_seconds() -> Result<u64, CommonError> {
        let Ok(timestamp_ms) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        else {
            return Err(CommonError::OtherError(
                "failed to retrieve std::time::UNIX_EPOCH".to_string(),
            ));
        };
        Ok(timestamp_ms.as_secs())
    }
}

#[allow(dead_code)]
impl BytesMutUtils {
    /// Convert `value` into `F`
    pub fn parse<F: FromStr>(value: &BytesMut) -> Option<F> {
        let value_as_number = String::from_utf8_lossy(&value[..]);
        let Ok(num) = F::from_str(&value_as_number) else {
            return None;
        };
        Some(num)
    }

    pub fn to_string(value: &[u8]) -> String {
        String::from_utf8_lossy(value).to_string()
    }

    pub fn from_string(value: &str) -> BytesMut {
        BytesMut::from(value)
    }

    pub fn from<N: std::fmt::Display>(value: &N) -> BytesMut {
        let as_str = format!("{}", value);
        BytesMut::from(as_str.as_str())
    }

    // conversion functions
    pub fn from_u64(num: &u64) -> BytesMut {
        let arr = num.to_be_bytes();
        BytesMut::from(&arr[..])
    }

    pub fn from_u8(ch: &u8) -> BytesMut {
        let arr = ch.to_be_bytes();
        BytesMut::from(&arr[..])
    }

    pub fn from_u16(short: &u16) -> BytesMut {
        let arr = short.to_be_bytes();
        BytesMut::from(&arr[..])
    }

    pub fn from_usize(size: &usize) -> BytesMut {
        let arr = size.to_be_bytes();
        BytesMut::from(&arr[..])
    }

    pub fn to_usize(bytes: &BytesMut) -> usize {
        let mut arr = [0u8; std::mem::size_of::<usize>()];
        arr.copy_from_slice(&bytes[0..std::mem::size_of::<usize>()]);
        usize::from_be_bytes(arr)
    }

    pub fn to_u64(bytes: &BytesMut) -> u64 {
        let mut arr = [0u8; std::mem::size_of::<u64>()];
        arr.copy_from_slice(&bytes[0..std::mem::size_of::<u64>()]);
        u64::from_be_bytes(arr)
    }

    pub fn to_u32(bytes: &BytesMut) -> u32 {
        let mut arr = [0u8; std::mem::size_of::<u32>()];
        arr.copy_from_slice(&bytes[0..std::mem::size_of::<u32>()]);
        u32::from_be_bytes(arr)
    }

    pub fn to_u8(bytes: &BytesMut) -> u8 {
        let mut arr = [0u8; std::mem::size_of::<u8>()];
        arr.copy_from_slice(&bytes[0..std::mem::size_of::<u8>()]);
        u8::from_be_bytes(arr)
    }

    pub fn to_u16(bytes: &BytesMut) -> u16 {
        let mut arr = [0u8; std::mem::size_of::<u16>()];
        arr.copy_from_slice(&bytes[0..std::mem::size_of::<u16>()]);
        u16::from_be_bytes(arr)
    }

    pub fn to_f64(bytes: &BytesMut) -> f64 {
        let mut arr = [0u8; std::mem::size_of::<f64>()];
        arr.copy_from_slice(&bytes[0..std::mem::size_of::<f64>()]);
        f64::from_be_bytes(arr)
    }

    pub fn from_f64(num: f64) -> BytesMut {
        let arr = num.to_be_bytes();
        BytesMut::from(&arr[..])
    }

    /// Given two sequences, return the longest subsequence present in both of them
    /// and the indices in each sequence
    pub fn lcs(seq1: &BytesMut, seq2: &BytesMut) -> (BytesMut, Vec<(usize, usize)>) {
        let m = seq1.len();
        let n = seq2.len();
        let mut table = vec![vec![0; n + 1]; m + 1];

        if seq1.is_empty() || seq2.is_empty() {
            return (BytesMut::new(), vec![]);
        }

        // Following steps build table[m+1][n+1] in bottom up
        // fashion. Note that table[i][j] contains length of LCS of
        // X[0..i-1] and Y[0..j-1]
        // the length of the LCS is at the bottom right cell of the table
        for i in 0..m + 1 {
            for j in 0..n + 1 {
                if i == 0 || j == 0 {
                    table[i][j] = 0;
                } else if seq1[i - 1] == seq2[j - 1] {
                    table[i][j] = table[i - 1][j - 1] + 1;
                } else {
                    table[i][j] = std::cmp::max(table[i - 1][j], table[i][j - 1]);
                }
            }
        }

        let mut indices = Vec::<(usize, usize)>::new();
        let mut i = m;
        let mut j = n;

        let mut lcs_str = BytesMut::with_capacity(table[m - 1][n - 1]);

        // Traverse the table
        while i > 0 && j > 0 {
            // If current character in X and Y is the same, then
            // the current character is part of the LCS
            if seq1[i - 1] == seq2[j - 1] {
                indices.insert(0, (i - 1, j - 1));
                let byte = seq1[i - 1];
                lcs_str.extend([byte]);
                // reduce values of i, j
                i -= 1;
                j -= 1;
            }
            // If not the same, then find the larger of two and
            // go in the direction of the larger value
            else if table[i - 1][j] > table[i][j - 1] {
                i -= 1;
            } else {
                j -= 1;
            }
        }

        lcs_str.reverse();
        (lcs_str, indices)
    }
}

pub enum CurrentTimeResolution {
    Nanoseconds,
    Microseconds,
    Milliseconds,
    Seconds,
}

/// Return the current timestamp since UNIX EPOCH - in seconds
pub fn current_time(res: CurrentTimeResolution) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("SystemTime::now");
    match res {
        CurrentTimeResolution::Nanoseconds => now.as_nanos().try_into().unwrap_or(u64::MAX),
        CurrentTimeResolution::Microseconds => now.as_micros().try_into().unwrap_or(u64::MAX),
        CurrentTimeResolution::Milliseconds => now.as_millis().try_into().unwrap_or(u64::MAX),
        CurrentTimeResolution::Seconds => now.as_secs(),
    }
}

/// Given list of values `options`, return up to `count` values.
/// The output is sorted.
pub fn choose_multiple_values(
    count: usize,
    options: &[usize],
    allow_dups: bool,
) -> Result<VecDeque<usize>, CommonError> {
    let mut rng = rand::rng();
    let mut chosen = Vec::<usize>::new();
    if allow_dups {
        for _ in 0..count {
            chosen.push(*options.choose(&mut rng).unwrap_or(&0));
        }
    } else {
        let mut unique_values = options.to_owned();
        unique_values.sort();
        unique_values.dedup();
        loop {
            if unique_values.is_empty() {
                break;
            }

            if chosen.len() == count {
                break;
            }

            let pos = rng.random_range(0..unique_values.len());
            let Some(val) = unique_values.get(pos) else {
                return Err(CommonError::OtherError(format!(
                    "Internal error: failed to read from vector (len: {}, pos: {})",
                    unique_values.len(),
                    pos
                )));
            };
            chosen.push(*val);
            unique_values.remove(pos);
        }
    }

    chosen.sort();
    let chosen: VecDeque<usize> = chosen.iter().copied().collect();
    Ok(chosen)
}

#[derive(Debug)]
pub struct IpPort {
    pub ip: String,
    pub port: u16,
}
