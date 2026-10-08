//! Load values from a pre-prepared dataset file.
//!
//! A dataset is a text file (optionally gzip compressed) where each line is
//! one value. The file is loaded once into memory, before the worker threads
//! start. The benchmark tests then pick a random line for every command.

use bytes::Bytes;
use flate2::read::MultiGzDecoder;
use rand::RngExt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Environment variable that holds the default dataset directory
pub const DATASET_DIR_ENV: &str = "SB_DATASET_DIR";

/// Dataset directory used when no directory is given and it exists
pub const DEFAULT_DATASET_DIR: &str = "dataset";

/// File name suffixes we try when the dataset is passed by name
const SUFFIXES: [&str; 5] = ["", ".gz", ".json.gz", ".jsonl.gz", ".json"];

static DATASET: OnceLock<Dataset> = OnceLock::new();

pub struct Dataset {
    path: PathBuf,
    values: Vec<Bytes>,
    total_bytes: usize,
}

impl Dataset {
    /// Load the dataset from `path`. Gzip content is detected by its magic bytes.
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read(path)
            .map_err(|e| format!("failed to read file '{}'. {}", path.display(), e))?;
        let content = if raw.starts_with(&[0x1f, 0x8b]) {
            let mut out = Vec::with_capacity(raw.len().saturating_mul(4));
            MultiGzDecoder::new(raw.as_slice())
                .read_to_end(&mut out)
                .map_err(|e| format!("failed to decompress '{}'. {}", path.display(), e))?;
            out
        } else {
            raw
        };
        Ok(Self::from_bytes(path.to_path_buf(), Bytes::from(content)))
    }

    /// Split `content` into lines. Each line is a zero-copy slice of `content`.
    /// Empty lines are skipped and a trailing "\r" is removed.
    fn from_bytes(path: PathBuf, content: Bytes) -> Self {
        let mut values = Vec::new();
        let mut total_bytes = 0usize;
        let mut start = 0usize;
        while start < content.len() {
            let end = memchr_newline(&content[start..])
                .map(|pos| start + pos)
                .unwrap_or(content.len());
            let mut line_end = end;
            if line_end > start && content[line_end - 1] == b'\r' {
                line_end -= 1;
            }
            if line_end > start {
                total_bytes += line_end - start;
                values.push(content.slice(start..line_end));
            }
            start = end + 1;
        }
        Dataset {
            path,
            values,
            total_bytes,
        }
    }

    /// Return a random value from the dataset
    #[inline]
    pub fn random_value(&self) -> &[u8] {
        let idx = rand::rng().random_range(0..self.values.len());
        &self.values[idx]
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Average value size, in bytes
    pub fn avg_value_size(&self) -> usize {
        self.total_bytes / self.values.len().max(1)
    }
}

/// Value size statistics, in bytes
#[derive(Debug, PartialEq)]
pub struct SizeStats {
    pub count: usize,
    pub total: usize,
    pub avg: usize,
    pub min: usize,
    pub p50: usize,
    pub p90: usize,
    pub p99: usize,
    pub max: usize,
}

impl Dataset {
    pub fn size_stats(&self) -> SizeStats {
        let mut sizes: Vec<usize> = self.values.iter().map(|v| v.len()).collect();
        sizes.sort_unstable();
        // nearest-rank percentile
        let pct = |p: usize| -> usize {
            if sizes.is_empty() {
                return 0;
            }
            let rank = (p * sizes.len()).div_ceil(100).max(1);
            sizes[rank - 1]
        };
        SizeStats {
            count: sizes.len(),
            total: self.total_bytes,
            avg: self.avg_value_size(),
            min: sizes.first().copied().unwrap_or(0),
            p50: pct(50),
            p90: pct(90),
            p99: pct(99),
            max: sizes.last().copied().unwrap_or(0),
        }
    }
}

/// Return the dataset name of `path`: the file name without a known suffix
fn dataset_name(path: &Path) -> String {
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    // longest suffix first, so "x.json.gz" becomes "x", not "x.json"
    let mut suffixes: Vec<&str> = SUFFIXES.iter().copied().filter(|s| !s.is_empty()).collect();
    suffixes.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for suffix in suffixes {
        if let Some(name) = file_name.strip_suffix(suffix) {
            return name.to_string();
        }
    }
    file_name
}

/// Print value size statistics for every dataset file in `dir`
pub fn print_datasets(dir: &Path) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("failed to read directory '{}'. {}", dir.display(), e))?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .filter(|p| {
            !p.file_name()
                .map(|n| n.to_string_lossy().starts_with('.'))
                .unwrap_or(true)
        })
        .collect();
    paths.sort();

    println!("Datasets in: {}", dir.display());
    println!(
        "{:<24} {:>10} {:>12} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "NAME", "VALUES", "TOTAL", "AVG", "MIN", "P50", "P90", "P99", "MAX"
    );
    for path in paths {
        let name = dataset_name(&path);
        match Dataset::load(&path) {
            Ok(ds) => {
                let st = ds.size_stats();
                println!(
                    "{:<24} {:>10} {:>12} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
                    name,
                    st.count,
                    human_size(st.total),
                    human_size(st.avg),
                    human_size(st.min),
                    human_size(st.p50),
                    human_size(st.p90),
                    human_size(st.p99),
                    human_size(st.max),
                );
            }
            Err(e) => println!("{:<24} error: {}", name, e),
        }
    }
    Ok(())
}

/// Format a byte count, for example: 512B, 3.0KB, 1.5MB
fn human_size(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    let b = bytes as f64;
    if b < KB {
        format!("{}B", bytes)
    } else if b < KB * KB {
        format!("{:.1}KB", b / KB)
    } else if b < KB * KB * KB {
        format!("{:.1}MB", b / (KB * KB))
    } else {
        format!("{:.1}GB", b / (KB * KB * KB))
    }
}

#[inline]
fn memchr_newline(buf: &[u8]) -> Option<usize> {
    buf.iter().position(|b| *b == b'\n')
}

/// Find the dataset file. `name` can be a path to a file, or a name that we look
/// up in `dir` (with or without a known suffix, for example: "taxi-trips"
/// matches "taxi-trips.json.gz").
pub fn resolve_path(name: &str, dir: &Path) -> Result<PathBuf, String> {
    let direct = PathBuf::from(name);
    if direct.is_file() {
        return Ok(direct);
    }

    for suffix in SUFFIXES {
        let candidate = dir.join(format!("{}{}", name, suffix));
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "could not find dataset '{}' in directory '{}'",
        name,
        dir.display()
    ))
}

/// Load the dataset and make it available to all threads. Call this once,
/// before the worker threads start.
pub fn init(name: &str, dir: &Path) -> Result<&'static Dataset, String> {
    let path = resolve_path(name, dir)?;
    let dataset = Dataset::load(&path)?;
    if dataset.len() == 0 {
        return Err(format!("dataset '{}' has no values", path.display()));
    }
    Ok(DATASET.get_or_init(|| dataset))
}

/// Return the loaded dataset, if any
pub fn get() -> Option<&'static Dataset> {
    DATASET.get()
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn test_split_lines() {
        let ds = Dataset::from_bytes(
            PathBuf::from("mem"),
            Bytes::from_static(b"one\r\ntwo\n\nthree"),
        );
        assert_eq!(ds.len(), 3);
        assert_eq!(&ds.values[0][..], b"one");
        assert_eq!(&ds.values[1][..], b"two");
        assert_eq!(&ds.values[2][..], b"three");
        assert_eq!(ds.avg_value_size(), 11 / 3);
    }

    #[test]
    fn test_size_stats() {
        let content: Vec<u8> = (1..=100)
            .flat_map(|n| {
                let mut line = vec![b'x'; n];
                line.push(b'\n');
                line
            })
            .collect();
        let ds = Dataset::from_bytes(PathBuf::from("mem"), Bytes::from(content));
        let st = ds.size_stats();
        assert_eq!(st.count, 100);
        assert_eq!(st.min, 1);
        assert_eq!(st.p50, 50);
        assert_eq!(st.p90, 90);
        assert_eq!(st.p99, 99);
        assert_eq!(st.max, 100);
        assert_eq!(st.avg, 5050 / 100);
    }

    #[test]
    fn test_dataset_name() {
        assert_eq!(dataset_name(Path::new("d/taxi-trips.json")), "taxi-trips");
        assert_eq!(dataset_name(Path::new("d/gh-50k.json.gz")), "gh-50k");
        assert_eq!(dataset_name(Path::new("d/other.gz")), "other");
        assert_eq!(dataset_name(Path::new("d/plain")), "plain");
    }

    #[test]
    fn test_load_gzip_and_resolve_by_name() {
        let dir = std::env::temp_dir().join(format!("sb-dataset-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("sample.json.gz");
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"{\"a\":1}\n{\"b\":2}\n").unwrap();
        std::fs::write(&file, enc.finish().unwrap()).unwrap();

        let path = resolve_path("sample", &dir).unwrap();
        assert_eq!(path, file);
        let ds = Dataset::load(&path).unwrap();
        assert_eq!(ds.len(), 2);
        let v = ds.random_value();
        assert!(v == b"{\"a\":1}" || v == b"{\"b\":2}");

        assert!(resolve_path("missing", &dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
