#![allow(clippy::trivially_copy_pass_by_ref)]

use anyhow::{bail, Result};
const MAX_PEEK_SIZE: usize = 1024;
use crate::data::File;
use ignore::gitignore::GitignoreBuilder;
use sha2::Digest;
use std::fs::File as FsFile;
use std::io;
use std::io::Read;
use std::path::Path;
use std::process;

struct CrcDigest(crc32fast::Hasher);

impl std::io::Write for CrcDigest {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn is_ext_class(file: &File, fval: &[String]) -> Result<Option<bool>> {
    file.ext
        .as_ref()
        .map_or(Ok(None), |ext| Ok(Some(fval.iter().any(|v| ext.eq(v)))))
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn is_archive(file: &File, fval: &[String]) -> Result<Option<bool>> {
    is_ext_class(file, fval)
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn is_document(file: &File, fval: &[String]) -> Result<Option<bool>> {
    is_ext_class(file, fval)
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn is_media(file: &File, fval: &[String]) -> Result<Option<bool>> {
    is_ext_class(file, fval)
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn is_code(file: &File, fval: &[String]) -> Result<Option<bool>> {
    is_ext_class(file, fval)
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn is_ignored(file: &File, fval: &[String]) -> Result<Option<bool>> {
    let mut gib = GitignoreBuilder::new(".");

    #[allow(clippy::needless_collect)]
    let errs = fval.iter().filter_map(|v| gib.add(v)).collect::<Vec<_>>();

    let gib = gib.build()?;
    if errs.is_empty() {
        Ok(Some(
            gib.matched(&file.abs_path, file.is_dir.unwrap_or(false))
                .is_ignore(),
        ))
    } else {
        bail!("error loading gitignore file(s)");
    }
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn crc32(file: &File, fval: &bool) -> Result<Option<String>> {
    if !fval {
        return Ok(None);
    }
    let path = Path::new(&file.abs_path);
    let mut file = FsFile::open(path)?;
    let mut hasher = CrcDigest(crc32fast::Hasher::new());
    io::copy(&mut file, &mut hasher)?;
    let hash = hasher.0.finalize();
    Ok(Some(format!("{:x}", hash)))
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn simhash(file: &File, fval: &bool) -> Result<Option<String>> {
    if !fval {
        return Ok(None);
    }
    let path = Path::new(&file.abs_path);
    let text = std::fs::read(path)?;
    let hash = simhash::simhash(&String::from_utf8_lossy(&text[..]));
    Ok(Some(format!("{:x}", hash))) // to convert back  u64::from_str_radix(src, radix)
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn bytes_type(file: &File, fval: &bool) -> Result<Option<String>> {
    if !fval {
        return Ok(None);
    }
    let path = Path::new(&file.abs_path);
    let file = FsFile::open(&path)?;
    let mut buffer: Vec<u8> = vec![];
    file.take(MAX_PEEK_SIZE as u64).read_to_end(&mut buffer)?;
    Ok(Some(content_inspector::inspect(&buffer).to_string()))
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn is_binary(file: &File, fval: &bool) -> Result<Option<bool>> {
    if !fval {
        return Ok(None);
    }

    // infer based on bytes type, if missing force compute it
    if let Some(bytes_type) = &file.bytes_type {
        return Ok(Some(bytes_type == "binary"));
    } else if let Some(bytes_type) = bytes_type(file, &true)? {
        return Ok(Some(bytes_type == "binary"));
    }

    Ok(None)
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn sha256(file: &File, fval: &bool) -> Result<Option<String>> {
    if !fval {
        return Ok(None);
    }
    let path = Path::new(&file.abs_path);
    let mut file = FsFile::open(path)?;
    let mut hasher = sha2::Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    let hash = hasher.finalize();
    Ok(Some(format!("{:x}", hash)))
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn sha512(file: &File, fval: &bool) -> Result<Option<String>> {
    if !fval {
        return Ok(None);
    }
    let path = Path::new(&file.abs_path);
    let mut file = FsFile::open(path)?;
    let mut hasher = sha2::Sha512::new();
    io::copy(&mut file, &mut hasher)?;
    let hash = hasher.finalize();
    Ok(Some(format!("{:x}", hash)))
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn md5(file: &File, fval: &bool) -> Result<Option<String>> {
    if !fval {
        return Ok(None);
    }
    let path = Path::new(&file.abs_path);
    let mut file = FsFile::open(path)?;
    let mut hasher = md5::Md5::new();
    io::copy(&mut file, &mut hasher)?;
    let hash = hasher.finalize();
    Ok(Some(format!("{:x}", hash)))
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn file_magic(file: &File, fval: &bool) -> Result<Option<String>> {
    if !fval {
        return Ok(None);
    }
    let path = Path::new(&file.abs_path);
    let out = process::Command::new("file").args([path]).output()?;
    Ok(Some(
        String::from_utf8_lossy(&out.stdout[..])
            .to_string()
            .replace(&format!("{}: ", &file.abs_path), ""),
    ))
}
