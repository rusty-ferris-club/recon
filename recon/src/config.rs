use anyhow::Result;
use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

///
/// Computed fields to add on to an indexed file
///
/// These fields are either too compute-intensive or use case specific and therefore
/// opt-in.
///
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct ComputedFields {
    pub is_archive: Option<Vec<String>>,
    pub is_document: Option<Vec<String>>,
    pub is_media: Option<Vec<String>>,
    pub is_code: Option<Vec<String>>,
    pub is_ignored: Option<Vec<String>>,

    pub bytes_type: Option<bool>,
    pub is_binary: Option<bool>,
    pub file_magic: Option<bool>,
    pub crc32: Option<bool>,
    pub sha256: Option<bool>,
    pub sha512: Option<bool>,
    pub md5: Option<bool>,
    pub simhash: Option<bool>,

    #[serde(default)]
    pub crc32_match: Option<Vec<String>>,
    #[serde(default)]
    pub sha256_match: Option<Vec<String>>,
    #[serde(default)]
    pub sha512_match: Option<Vec<String>>,
    #[serde(default)]
    pub md5_match: Option<Vec<String>>,
    #[serde(default)]
    pub simhash_match: Option<Vec<String>>,

    #[serde(with = "serde_regex")]
    #[serde(default)]
    pub path_match: Option<Regex>,

    #[serde(with = "serde_regex")]
    #[serde(default)]
    pub content_match: Option<regex::bytes::Regex>,

    #[serde(default)]
    pub yara_match: Option<String>,
}

///
/// A source to index
///
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Source {
    #[serde(default)]
    pub root: Option<String>,

    #[serde(default)]
    pub query: Option<String>,

    #[serde(default)]
    pub before_computed_fields_query: Option<String>,

    #[serde(default)]
    pub unpack: Option<bool>,

    #[serde(default)]
    pub default_fields: Option<ComputedFields>,

    #[serde(default)]
    pub computed_fields: Option<ComputedFields>,
}

impl Source {
    #[must_use]
    pub fn root(&self) -> String {
        self.root.clone().unwrap_or_else(|| ".".to_string())
    }

    #[must_use]
    pub fn query(&self) -> String {
        self.before_computed_fields_query
            .clone()
            .unwrap_or_else(|| "select * from files".to_string())
    }

    #[must_use]
    pub fn default_fields(&self) -> ComputedFields {
        self.default_fields.clone().unwrap_or_default()
    }

    #[must_use]
    pub fn computed_fields(&self) -> ComputedFields {
        self.computed_fields.clone().unwrap_or_default()
    }
}

///
/// A configuration object
/// includes an index source
///
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub source: Source,
}

impl Config {
    /// load configuration from text
    ///
    /// # Errors
    ///
    /// This function will return an error on parse failure
    #[tracing::instrument(level = "trace", skip_all, err)]
    pub fn from_text(text: &str) -> Result<Self> {
        let conf: Self = serde_yaml::from_str(text)?;
        Ok(conf)
    }

    /// load configuration from file
    ///
    /// # Errors
    ///
    /// This function will return an error on I/O failure
    #[tracing::instrument(level = "trace", skip_all, err)]
    pub fn from_path(file: &Path) -> Result<Self> {
        Self::from_text(&fs::read_to_string(file)?)
    }
}
