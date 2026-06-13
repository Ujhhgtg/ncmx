use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use aes::Aes128Dec;
use aes::cipher::{BlockCipherDecrypt, KeyInit};
use base64::Engine;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CORE_KEY: [u8; 16] = [
    0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57,
];

const MODIFY_KEY: [u8; 16] = [
    0x23, 0x31, 0x34, 0x6C, 0x6A, 0x6B, 0x5F, 0x21, 0x5C, 0x5D, 0x26, 0x30, 0x55, 0x3C, 0x27, 0x28,
];

const PNG_HEADER: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AudioFormat {
    Flac,
    Mp3,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SongMeta {
    pub name: String,
    pub album: String,
    pub artist: String,
    pub bitrate: i64,
    pub duration: i64,
    pub format: String,
}

pub struct NcmFile {
    file: File,
    path: PathBuf,
    key_box: [u8; 256],
    format: Option<AudioFormat>,
    dump_path: Option<PathBuf>,
    metadata: Option<SongMeta>,
    image_data: Vec<u8>,
    album_pic_url: String,
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn read_exact<R: Read>(reader: &mut R, size: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// AES-128-ECB decrypt with PKCS7 unpadding.
fn aes_ecb_decrypt(key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes128Dec::new(key.into());
    let mut buf = data.to_vec();
    for chunk in buf.chunks_exact_mut(16) {
        cipher.decrypt_block(chunk.try_into().unwrap());
    }
    // PKCS7 unpadding
    let pad_len = buf[buf.len() - 1] as usize;
    if pad_len <= 16 {
        buf.truncate(buf.len() - pad_len);
    }
    buf
}

/// Build the 256-byte key box from decrypted key material.
fn build_key_box(key: &[u8]) -> [u8; 256] {
    let mut box_: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut last: u8 = 0;
    let mut key_offset = 0;
    for i in 0..256usize {
        let swap = box_[i];
        let c = swap.wrapping_add(last).wrapping_add(key[key_offset]);
        key_offset = (key_offset + 1) % key.len();
        box_[i] = box_[c as usize];
        box_[c as usize] = swap;
        last = c;
    }
    box_
}

// ---------------------------------------------------------------------------
// NcmFile implementation
// ---------------------------------------------------------------------------

impl NcmFile {
    /// Open and parse an .ncm file.
    ///
    /// Validates the magic header, reads and decrypts the key material, metadata,
    /// and embedded cover image, and builds the key box for audio decryption.
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;

        // --- Validate magic header: "NETCMADF" ---
        let magic1 = read_exact(&mut file, 4)?;
        if u32::from_le_bytes(magic1[..4].try_into()?) != 0x4E455443 {
            return Err("not a .ncm file (bad magic 1)".into());
        }
        let magic2 = read_exact(&mut file, 4)?;
        if u32::from_le_bytes(magic2[..4].try_into()?) != 0x4D414446 {
            return Err("not a .ncm file (bad magic 2)".into());
        }

        // --- Skip version (2 bytes) ---
        file.seek(SeekFrom::Current(2))?;

        // --- Read encrypted key length ---
        let key_len_raw = read_exact(&mut file, 4)?;
        let key_len = u32::from_le_bytes(key_len_raw[..4].try_into()?) as usize;

        // --- Read and XOR-decrypt key data (XOR 0x64) ---
        let mut key_data = read_exact(&mut file, key_len)?;
        for b in &mut key_data {
            *b ^= 0x64;
        }

        // --- AES-128-ECB decrypt with CORE_KEY ---
        let decrypted_key = aes_ecb_decrypt(&CORE_KEY, &key_data);

        // --- Build key box from key material (skip first 17 bytes) ---
        let key_box = build_key_box(&decrypted_key[17..]);

        // --- Read metadata length ---
        let meta_len_raw = read_exact(&mut file, 4)?;
        let meta_len = u32::from_le_bytes(meta_len_raw[..4].try_into()?) as usize;

        let (metadata, album_pic_url) = if meta_len > 0 {
            // Read and XOR-decrypt metadata (XOR 0x63)
            let mut modify_data = read_exact(&mut file, meta_len)?;
            for b in &mut modify_data {
                *b ^= 0x63;
            }

            // Strip "163 key(Don't modify):" prefix (22 bytes)
            let b64_input = std::str::from_utf8(&modify_data[22..])
                .map_err(|_| "invalid metadata UTF-8 after XOR")?;

            // Base64 decode
            let modify_out =
                base64::engine::general_purpose::STANDARD.decode(b64_input.as_bytes())?;

            // AES-128-ECB decrypt with MODIFY_KEY
            let modify_decrypt = aes_ecb_decrypt(&MODIFY_KEY, &modify_out);

            // Strip "music:" prefix (6 bytes)
            let meta_json = std::str::from_utf8(&modify_decrypt[6..])
                .map_err(|_| "invalid metadata JSON UTF-8")?;

            // Parse JSON
            let v: Value = serde_json::from_str(meta_json)?;

            let name = v
                .get("musicName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let album = v
                .get("album")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let artist = v
                .get("artist")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|a| {
                            a.as_array()
                                .and_then(|inner| inner.first())
                                .and_then(|f| f.as_str())
                        })
                        .collect::<Vec<_>>()
                        .join(" / ")
                })
                .unwrap_or_default();

            let bitrate = v.get("bitrate").and_then(|v| v.as_i64()).unwrap_or(0);
            let duration = v.get("duration").and_then(|v| v.as_i64()).unwrap_or(0);
            let format = v
                .get("format")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let pic_url = v
                .get("albumPic")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let meta = SongMeta {
                name,
                album,
                artist,
                bitrate,
                duration,
                format,
            };

            (Some(meta), pic_url)
        } else {
            (None, String::new())
        };

        // --- Skip 5-byte gap ---
        file.seek(SeekFrom::Current(5))?;

        // --- Read cover frame ---
        let cf_len_raw = read_exact(&mut file, 4)?;
        let cf_total = u32::from_le_bytes(cf_len_raw[..4].try_into()?) as i64;

        let cd_len_raw = read_exact(&mut file, 4)?;
        let cd_len = u32::from_le_bytes(cd_len_raw[..4].try_into()?) as usize;

        let image_data = if cd_len > 0 {
            read_exact(&mut file, cd_len)?
        } else {
            Vec::new()
        };

        // Skip remaining cover frame padding
        let remaining = cf_total - cd_len as i64;
        if remaining > 0 {
            file.seek(SeekFrom::Current(remaining))?;
        }

        Ok(NcmFile {
            file,
            path: path.to_path_buf(),
            key_box,
            format: None,
            dump_path: None,
            metadata,
            image_data,
            album_pic_url,
        })
    }

    /// Decrypt the audio data and write the output file.
    ///
    /// Detects the output format (FLAC vs MP3) from the first decrypted bytes.
    /// If `target_dir` is `Some`, the output file is placed in that directory
    /// (only the filename is kept from the original path).
    pub fn dump(&mut self, target_dir: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
        let mut dump_path = self.path.clone();
        let mut buffer = vec![0u8; 0x8000];
        let mut format_detected = false;
        let mut output_file: Option<File> = None;

        loop {
            let n = self.file.read(&mut buffer)?;
            if n == 0 {
                break;
            }

            // Decrypt each byte using the key box
            for i in 0..n {
                let j = (i + 1) & 0xff;
                let idx = (self.key_box[j] as usize
                    + self.key_box[(self.key_box[j] as usize + j as usize) & 0xff] as usize)
                    & 0xff;
                buffer[i] ^= self.key_box[idx];
            }

            if !format_detected {
                // Detect format from the first decrypted bytes
                if n >= 3 && buffer[0] == 0x49 && buffer[1] == 0x44 && buffer[2] == 0x33 {
                    self.format = Some(AudioFormat::Mp3);
                    dump_path.set_extension("mp3");
                } else {
                    self.format = Some(AudioFormat::Flac);
                    dump_path.set_extension("flac");
                }

                if let Some(dir) = target_dir {
                    let fname = dump_path.file_name().ok_or("invalid filename")?;
                    dump_path = dir.join(fname);
                }

                format_detected = true;
                output_file = Some(File::create(&dump_path)?);
            }

            if let Some(ref mut out) = output_file {
                out.write_all(&buffer[..n])?;
            }
        }

        self.dump_path = Some(dump_path);
        Ok(())
    }

    /// Write metadata (title, artist, album, cover art) into the dumped audio file.
    ///
    /// If `fetch_album_art` is true and no cover image was embedded in the .ncm file,
    /// attempts to download it from the NetEase server.
    pub fn fix_metadata(&self, fetch_album_art: bool) -> Result<(), Box<dyn std::error::Error>> {
        let dump_path = self
            .dump_path
            .as_ref()
            .ok_or("cannot fix metadata: file has not been dumped yet")?
            .clone();

        let mut image_data = self.image_data.clone();

        // Fetch album art from remote if not embedded
        if image_data.is_empty() && fetch_album_art && !self.album_pic_url.is_empty() {
            if let Ok(resp) = reqwest::blocking::get(&self.album_pic_url) {
                if resp.status().is_success() {
                    if let Ok(bytes) = resp.bytes() {
                        image_data = bytes.to_vec();
                    }
                }
            }
        }

        use lofty::config::WriteOptions;
        use lofty::picture::{MimeType, Picture, PictureType};
        use lofty::prelude::*;
        use lofty::read_from_path;

        let mut tagged_file = read_from_path(&dump_path)?;
        let tag = tagged_file
            .primary_tag_mut()
            .ok_or("no primary tag found in audio file")?;

        if let Some(ref meta) = self.metadata {
            if !meta.name.is_empty() {
                tag.set_title(meta.name.clone());
            }
            if !meta.artist.is_empty() {
                tag.set_artist(meta.artist.clone());
            }
            if !meta.album.is_empty() {
                tag.set_album(meta.album.clone());
            }
        }

        if !image_data.is_empty() {
            let mime = if image_data.starts_with(&PNG_HEADER) {
                MimeType::Png
            } else {
                MimeType::Jpeg
            };

            let picture = Picture::unchecked(image_data)
                .pic_type(PictureType::CoverFront)
                .mime_type(mime)
                .description("Cover")
                .build();
            tag.set_picture(0, picture);
        }

        tag.save_to_path(&dump_path, WriteOptions::default())?;

        Ok(())
    }

    /// Path to the dumped audio file, if `dump()` has been called.
    pub fn dump_path(&self) -> Option<&Path> {
        self.dump_path.as_deref()
    }

    /// Detected audio format, if `dump()` has been called.
    #[allow(dead_code)]
    pub fn format(&self) -> Option<AudioFormat> {
        self.format
    }
}
