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
use decompress::{decompress, ExtractOpts, Decompression};
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::json;
use sqlx::pool::PoolConnection;
use sqlx::sqlite::SqliteColumn;
use sqlx::sqlite::SqliteRow;
use sqlx::{Column, Row, SqlitePool, TypeInfo, Value, ValueRef};
use sqlx::{Pool, Sqlite};

use anyhow::Context;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

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
#[derive(Default, Debug, Clone, sqlx::FromRow)]
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
        let size = m.and_then(|m| (m.len() as u64).try_into().ok());
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

    pub(crate) fn unpack(&self) -> Result<Decompression> {
        let file_path = Path::new(&self.abs_path);
        let extract_to = file_path.parent().unwrap();

        return decompress(
            file_path, 
            extract_to, 
            &ExtractOpts{ strip: 0 }
        ).context(format!("failed to unpack file {}", file_path.display()));
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

/// For a slice of materialized `File`s, fill in extra computed fields and store results (should upsert) in DB
///
/// # Errors
///
/// This function will return an error on data processing or database access failure
#[tracing::instrument(level = "trace", skip_all, err)]
pub(crate) async fn compute_fields_and_store(
    files: &[File],
    fields: &ComputedFields,
    s: &ProgressBar,
    pool: &Pool<Sqlite>,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    s.set_length(files.len() as u64);
    s.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:16.cyan/blue} {pos:>7}/{len:7} {msg}",
        )
        .unwrap(),
    );
    s.set_position(
        files
            .iter()
            .filter(|f| f.computed.unwrap_or_default())
            .count() as u64,
    );
    for file in files.iter().filter(|f| !f.computed.unwrap_or_default()) {
        // a file may be in DB, but no longer on disk.
        let mut new_file = if Path::new(&file.abs_path).exists() {
            file.process_fields(fields)?
        } else {
            file.clone()
        };
        s.set_message("Computing fields".to_string());
        new_file.computed = Some(true);
        insert_one(&new_file, &mut conn).await?;
        s.inc(1);
    }
    Ok(())
}
/// Connect and migrate db
///
/// # Errors
///
/// This function will return an error on db failure
pub(crate) async fn connect(db_url: &str) -> Result<Pool<Sqlite>> {
    let pool = SqlitePool::connect(db_url).await?;
    sqlx::migrate!().run(&pool).await?; // embeds ./migrations
    Ok(pool)
}

/// Query into a `Vec` of files, materialized, for dealing with native `File`s.
///
/// # Errors
///
/// This function will return an error on db failure
#[tracing::instrument(level = "trace", skip_all, err)]
pub(crate) async fn query_files(q: &str, pool: &Pool<Sqlite>) -> anyhow::Result<Vec<File>> {
    let mut conn = pool.acquire().await?;
    let res = sqlx::query_as::<_, File>(q).fetch_all(&mut conn).await;
    res.context("error while performing query")
}
/// Query database
///
/// # Errors
///
/// This function will return an error on db failure
#[tracing::instrument(level = "trace", skip_all, err)]
pub(crate) async fn exists(f: &File, conn: &mut PoolConnection<Sqlite>) -> anyhow::Result<bool> {
    let total_rows: u32 = sqlx::query_scalar("select count(*) from files where abs_path=?")
        .bind(&f.abs_path)
        .fetch_one(conn)
        .await?;
    Ok(total_rows != 0)
}
/// Query database
///
/// # Errors
///
/// This function will return an error on db failure
#[tracing::instrument(level = "trace", skip_all, err)]
pub(crate) async fn query(q: &str, pool: &Pool<Sqlite>) -> anyhow::Result<ValuesTable> {
    let mut conn = pool.acquire().await?;
    let res = sqlx::query(q).fetch_all(&mut conn).await?;
    let total_rows: u32 = sqlx::query_scalar("select count(*) from files")
        .fetch_one(&mut conn)
        .await?;
    let first = res.first();
    first.map_or_else(
        || Ok(ValuesTable::default()),
        |first| {
            let columns = first
                .columns()
                .iter()
                .map(|c| c.name().to_string())
                .collect::<Vec<_>>();

            let rows = res
                .iter()
                .map(|row| {
                    first
                        .columns()
                        .iter()
                        .map(|col| repr_col(row, col))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            Ok(ValuesTable {
                columns,
                rows,
                total_rows,
            })
        },
    )
}

/// Upserts one file into db. Ugly and verbose implementation.
///
/// # Errors
///
/// This function will return an error on db failure
#[tracing::instrument(level = "trace", skip_all, err)]
pub(crate) async fn insert_one(f: &File, txn: &mut PoolConnection<Sqlite>) -> anyhow::Result<()> {
    sqlx::query(
        r#"
            INSERT INTO files (
                            entry_time,
                            abs_path,

                            path,
                            ext,
                            mode,

                            is_dir,
                            is_file,
                            is_symlink,
                            is_empty,
                            is_binary,

                            size,

                            user,
                            'group',
                            uid,
                            gid,

                            atime,
                            mtime,
                            ctime,

                            is_archive,
                            is_document,
                            is_media,
                            is_code,
                            is_ignored,

                            bytes_type,
                            file_magic,
                            crc32,
                            sha256,
                            sha512,
                            md5,
                            simhash,

                            crc32_match,
                            sha256_match,
                            sha512_match,
                            md5_match,
                            simhash_match,
                            path_match,
                            content_match,
                            yara_match,

                            computed
                ) VALUES (
                    ?,?,
                    ?,?,?,
                    ?,?,?,?,?,
                    ?,
                    ?,?,?,?,
                    ?,?,?,
                    ?,?,?,?,?,
                    ?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,
                    ?
                )
                ON CONFLICT(abs_path) DO UPDATE SET 
                            entry_time=excluded.entry_time,

                            path=excluded.path,
                            ext=excluded.ext,
                            mode=excluded.mode,

                            is_dir=excluded.is_dir,
                            is_file=excluded.is_file,
                            is_symlink=excluded.is_symlink,
                            is_empty=excluded.is_empty,
                            is_binary=excluded.is_binary,

                            size=excluded.size,

                            user=excluded.user,
                            'group'=excluded.'group',
                            uid=excluded.uid,
                            gid=excluded.gid,

                            atime=excluded.atime,
                            mtime=excluded.mtime,
                            ctime=excluded.ctime,

                            is_archive=excluded.is_archive,
                            is_document=excluded.is_document,
                            is_media=excluded.is_media,
                            is_code=excluded.is_code,
                            is_ignored=excluded.is_ignored,

                            bytes_type=excluded.bytes_type,
                            file_magic=excluded.file_magic,
                            crc32=excluded.crc32,
                            sha256=excluded.sha256,
                            sha512=excluded.sha512,
                            md5=excluded.md5,
                            simhash=excluded.simhash,

                            crc32_match=excluded.crc32_match,
                            sha256_match=excluded.sha256_match,
                            sha512_match=excluded.sha512_match,
                            md5_match=excluded.md5_match,
                            simhash_match=excluded.simhash_match,
                            path_match=excluded.path_match,
                            content_match=excluded.content_match,
                            yara_match=excluded.yara_match,

                            computed=excluded.computed
                            ;
            "#,
    )
    .bind(&f.entry_time)
    .bind(&f.abs_path)
    .bind(&f.path)
    .bind(&f.ext)
    .bind(&f.mode)
    .bind(&f.is_dir)
    .bind(&f.is_file)
    .bind(&f.is_symlink)
    .bind(&f.is_empty)
    .bind(&f.is_binary)
    .bind(&f.size)
    .bind(&f.user)
    .bind(&f.group)
    .bind(&f.uid)
    .bind(&f.gid)
    .bind(&f.atime)
    .bind(&f.mtime)
    .bind(&f.ctime)
    .bind(&f.is_archive)
    .bind(&f.is_document)
    .bind(&f.is_media)
    .bind(&f.is_code)
    .bind(&f.is_ignored)
    .bind(&f.bytes_type)
    .bind(&f.file_magic)
    .bind(&f.crc32)
    .bind(&f.sha256)
    .bind(&f.sha512)
    .bind(&f.md5)
    .bind(&f.simhash)
    .bind(&f.crc32_match)
    .bind(&f.sha256_match)
    .bind(&f.sha512_match)
    .bind(&f.md5_match)
    .bind(&f.simhash_match)
    .bind(&f.path_match)
    .bind(&f.content_match)
    .bind(&f.yara_match)
    .bind(&f.computed)
    .execute(txn)
    .await?;
    Ok(())
}

/// Clears data
///
/// # Errors
///
/// This function will return an error on db access failure
#[tracing::instrument(level = "trace", skip_all, err)]
pub(crate) async fn clear(pool: &Pool<Sqlite>) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    sqlx::query(
        r#"
        DELETE from files
      "#,
    )
    .execute(&mut conn)
    .await?;
    Ok(())
}

/// Represent a column as a JSON Value.
/// `json::Value` is just a more popular "general type holder" to use,
/// and so is better for upstream formatting, exports, and data manipulation
///
/// # Panics
///
/// Panics if sqlite has a column type we didn't handle
#[must_use]
pub fn repr_col(row: &SqliteRow, col: &SqliteColumn) -> serde_json::Value {
    let val_ref = row.try_get_raw(col.ordinal()).unwrap();
    let val = ValueRef::to_owned(&val_ref);
    let val = if val.is_null() {
        Ok(serde_json::Value::Null)
    } else {
        let ty_info = val.type_info();
        match ty_info.name() {
            "BOOLEAN" => val.try_decode::<bool>().map(serde_json::Value::Bool),
            "TINYINT UNSIGNED" | "SMALLINT UNSIGNED" | "INT UNSIGNED" | "MEDIUMINT UNSIGNED"
            | "BIGINT UNSIGNED" | "INTEGER" => {
                val.try_decode::<i64>().map(|t| serde_json::json!(t))
            }
            "TINYINT" | "SMALLINT" | "INT" | "MEDIUMINT" | "BIGINT" => {
                val.try_decode::<i64>().map(|t| serde_json::json!(t))
            }
            "FLOAT" => val.try_decode::<f32>().map(|t| serde_json::json!(t)),
            "DOUBLE" => val.try_decode::<f64>().map(|t| serde_json::json!(t)),
            "NULL" => Ok(json!("NULL")),
            "DATE" => val
                .try_decode::<DateTime<Utc>>()
                .map(|t| serde_json::json!(t.to_string())),
            "TIME" => val
                .try_decode::<DateTime<Utc>>()
                .map(|t| serde_json::json!(t.to_string())),
            "YEAR" => val.try_decode::<i64>().map(|t| json!(t)),
            // NOTE not sure for this
            "DATETIME" => val
                .try_decode::<DateTime<Utc>>()
                .map(|t| json!(t.to_string())),
            "TIMESTAMP" => val
                .try_decode::<chrono::DateTime<Utc>>()
                .map(|t| json!(t.to_string())),
            "GEOMETRY" | "JSON" => val.try_decode::<String>().map(|t| json!(t)),
            "CHAR" | "VARCHAR" | "TINYTEXT" | "TEXT" | "MEDIUMTEXT" | "LONGTEXT" => {
                val.try_decode::<String>().map(serde_json::Value::String)
            }
            "TINYBLOB" | "BLOB" | "MEDIUMBLOB" | "LONGBLOB" | "BINARY" | "VARBINARY" => {
                val.try_decode::<Vec<u8>>().map(|t| json!(t))
            }
            t => unreachable!("{}", t),
        }
    };
    val.unwrap()
}
