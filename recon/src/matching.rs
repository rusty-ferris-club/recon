use crate::data::File;
use crate::data::Match;
use anyhow::bail;
use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File as FsFile;
use std::io::Read;
use std::path::Path;

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn yara_match(file: &File, rules: &str) -> Result<Option<Match>> {
    let path = Path::new(&file.abs_path);
    let mut f = FsFile::open(path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;

    let compiler = yara::Compiler::new()?;
    let compiler = compiler.add_rules_str(rules)?;
    let rules = compiler.compile_rules()?;

    let res = rules.scan_mem(&data[..], 5)?;
    // parse out matches into a kind of bit map
    let by = res
        .iter()
        .map(|r| (r.identifier.to_string(), true))
        .collect::<HashMap<String, bool>>();

    Ok(Some(Match {
        is_match: !res.is_empty(),
        on: file.abs_path.to_string(),
        by,
        details: Some(serde_json::to_value(&res)?),
    }))
}

pub fn value_match(
    on: &str,
    name: &str,
    val: Option<&String>,
    vals: &[String],
) -> Result<Option<Match>> {
    if let Some(val) = val {
        Ok(Some(Match {
            is_match: vals.iter().any(|v| val.eq(v)),
            on: on.to_string(),
            by: HashMap::from([(name.to_string(), true)]),
            ..Default::default()
        }))
    } else {
        bail!(format!("{} value was not computed", name))
    }
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn crc32_match(file: &File, vals: &[String]) -> Result<Option<Match>> {
    value_match(&file.abs_path, "crc32", file.crc32.as_ref(), vals)
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn sha256_match(file: &File, vals: &[String]) -> Result<Option<Match>> {
    value_match(&file.abs_path, "sha256", file.sha256.as_ref(), vals)
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn sha512_match(file: &File, vals: &[String]) -> Result<Option<Match>> {
    value_match(&file.abs_path, "sha512", file.sha512.as_ref(), vals)
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn md5_match(file: &File, vals: &[String]) -> Result<Option<Match>> {
    value_match(&file.abs_path, "md5", file.md5.as_ref(), vals)
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn simhash_match(file: &File, vals: &[String]) -> Result<Option<Match>> {
    value_match(&file.abs_path, "simhash", file.simhash.as_ref(), vals)
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn path_match(file: &File, re: &Regex) -> Result<Option<Match>> {
    Ok(Some(Match {
        is_match: re.is_match(&file.abs_path),
        on: file.abs_path.to_string(),
        by: HashMap::from([("path".to_string(), true)]),
        ..Default::default()
    }))
}

#[tracing::instrument(level = "trace", skip_all, err)]
pub fn content_match(file: &File, re: &regex::bytes::Regex) -> Result<Option<Match>> {
    let path = Path::new(&file.abs_path);
    let content = std::fs::read(path)?;
    Ok(Some(Match {
        is_match: re.is_match(&content),
        on: file.abs_path.to_string(),
        by: HashMap::from([("content".to_string(), true)]),
        ..Default::default()
    }))
}
