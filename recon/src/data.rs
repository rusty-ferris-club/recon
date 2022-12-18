use crate::matching::{
    content_match, crc32_match, md5_match, path_match, sha256_match, sha512_match, simhash_match,
    yara_match,
};
use crate::os;
use crate::out::{to_csv, to_json, to_table, to_xargs};
use crate::processing::{
    bytes_type, crc32, file_magic, is_archive, is_binary, is_code, is_document, is_ignored,
    is_media, md5, sha256, sha512, simhash,
};

use anyhow::Context;
use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use sqlx_meta::SqlxMeta;
use std::collections::HashMap;
use std::fs;

use ignore::DirEntry;

use crate::{
    config::ComputedFields,
    os::{ftime, user_and_group},
};

pub const DB_FILE: &str = "recon.db";

macro_rules! process_content {
    ($name:ident, $fields:ident, $file:ident) => {
        if let Some(fval) = &$fields.$name {
            $file.$name = $name(&$file, fval)
                .with_context(|| format!("{} on '{}'", stringify!($name), $file.path))?
                .map(|t| t.into());
        }
    };
}
macro_rules! process_match {
    ($name:ident, $fields:ident, $file:ident) => {
        if let Some(fval) = &$fields.$name {
            $file.$name = $name(&$file, fval)?.map(Json);
        }
    };
}

///
/// A table of result values for a query
/// Useful for dynamic data manipulation or display
///
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ValuesTable {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub total_rows: u32,
}

impl ValuesTable {
    /// Export as csv
    ///
    /// # Errors
    ///
    /// This function will return an error on I/O failure
    pub fn to_csv(&self) -> Result<String> {
        to_csv(self)
    }

    /// Convert to a xargs-friendly format (a newline separated list of values)
    ///
    /// # Errors
    ///
    /// This function is not expected to error, just conforms to an interface
    pub fn to_xargs(&self) -> Result<String> {
        to_xargs(self)
    }

    /// Export as JSON
    ///
    /// # Errors
    ///
    /// This function will return an error on serialization failure
    pub fn to_json(&self) -> Result<String> {
        to_json(self)
    }

    /// Returns an ASCII drawn table
    ///
    /// # Errors
    ///
    /// This function is not expected to error, just conforms to an interface
    pub fn to_table(&self) -> Result<String> {
        to_table(self)
    }
}

///
/// A match representation for the matcher computed field types
///
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    pub is_match: bool,
    pub on: String,
    pub by: HashMap<String, bool>,
    pub details: Option<serde_json::Value>,
}

///
/// The main file abstraction. Contains basic file data, metadata, and computed fields
///
#[derive(Default, Debug, Clone, sqlx::FromRow, SqlxMeta)]
pub struct File {
    pub id: Option<i32>,
    pub entry_time: String,
    pub abs_path: String,
    pub path: String,
    pub ext: Option<String>,
    pub mode: Option<String>,
    pub is_dir: Option<bool>,
    pub is_file: Option<bool>,
    pub is_symlink: Option<bool>,
    pub is_empty: bool,
    pub is_binary: Option<bool>,
    pub size: Option<i64>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub atime: Option<chrono::DateTime<Utc>>,
    pub mtime: Option<chrono::DateTime<Utc>>,
    pub ctime: Option<chrono::DateTime<Utc>>,

    pub is_archive: Option<bool>,
    pub is_document: Option<bool>,
    pub is_media: Option<bool>,
    pub is_code: Option<bool>,
    pub is_ignored: Option<bool>,

    pub bytes_type: Option<String>,
    pub file_magic: Option<String>,
    pub crc32: Option<String>,
    pub sha256: Option<String>,
    pub sha512: Option<String>,
    pub md5: Option<String>,
    pub simhash: Option<String>,

    pub crc32_match: Option<Json<Match>>,
    pub sha256_match: Option<Json<Match>>,
    pub sha512_match: Option<Json<Match>>,
    pub md5_match: Option<Json<Match>>,
    pub simhash_match: Option<Json<Match>>,
    pub path_match: Option<Json<Match>>,
    pub content_match: Option<Json<Match>>,
    pub yara_match: Option<Json<Match>>,

    pub computed: Option<bool>,
}

impl File {
    /// Build a `File` from a walker entry.
    ///
    /// # Errors
    ///
    /// This function will return an error on IO or processing failure
    ///
    pub(crate) fn from_entry(entry: &DirEntry) -> Result<Self> {
        let path = entry.path().display().to_string();
        let m_v = entry.metadata().ok();
        let m = m_v.as_ref();
        let (user, group, uid, gid) = m.map_or((None, None, None, None), user_and_group);
        let size = m.and_then(|m| m.len().try_into().ok());
        let is_file = m.map(fs::Metadata::is_file);

        Ok(Self {
            entry_time: chrono::Utc::now().to_rfc3339(),
            path,
            ext: entry
                .path()
                .extension()
                .map(|s| s.to_string_lossy().to_string()),
            abs_path: fs::canonicalize(entry.path())?
                .to_string_lossy()
                .to_string(),
            mode: m.map(|m| unix_mode::to_string(os::mode(m))),
            is_dir: m.map(fs::Metadata::is_dir),
            is_file,
            is_symlink: m.map(fs::Metadata::is_symlink),
            is_empty: size.map_or(false, |s| s == 0),
            size,
            user,
            group,
            uid,
            gid,
            atime: m.and_then(|m| ftime(m.accessed())),
            mtime: m.and_then(|m| ftime(m.modified())),
            ctime: m.and_then(|m| ftime(m.created())),
            ..Self::default()
        })
    }

    pub(crate) fn process_fields(&self, fields: &ComputedFields) -> Result<Self> {
        compute_fields(self, fields)
    }
}

/// Compute all on-demand fields as configured in `ComputedFields`.
///
/// # Errors
///
/// This function will return an error on processing failure
#[tracing::instrument(level = "trace", skip_all, err)]
pub fn compute_fields(file: &File, fields: &ComputedFields) -> Result<File> {
    let mut f = file.clone();

    process_content!(is_archive, fields, f);
    process_content!(is_document, fields, f);
    process_content!(is_media, fields, f);
    process_content!(is_code, fields, f);
    process_content!(is_ignored, fields, f);

    process_content!(bytes_type, fields, f);
    process_content!(is_binary, fields, f);
    process_content!(file_magic, fields, f);
    process_content!(crc32, fields, f);
    process_content!(sha256, fields, f);
    process_content!(sha512, fields, f);
    process_content!(md5, fields, f);
    process_content!(simhash, fields, f);

    process_match!(yara_match, fields, f);
    process_match!(crc32_match, fields, f);
    process_match!(sha256_match, fields, f);
    process_match!(sha512_match, fields, f);
    process_match!(md5_match, fields, f);
    process_match!(simhash_match, fields, f);
    process_match!(path_match, fields, f);
    process_match!(content_match, fields, f);

    Ok(f)
}
