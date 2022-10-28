use std::env;

use crate::data::ValuesTable;
use anyhow::{Context, Result};
use csv::Writer;
use regex::Regex;

/// Represent a value as string
fn repr(col: &serde_json::Value) -> String {
    col.as_str()
        .map_or_else(|| col.to_string(), ToString::to_string)
}

/// Export as csv
///
/// # Errors
///
/// This function will return an error on I/O failure
pub fn to_csv(vt: &ValuesTable) -> Result<String> {
    let mut wtr = Writer::from_writer(vec![]);
    for row in &vt.rows {
        wtr.write_record(row.iter().map(repr))?;
    }
    String::from_utf8(wtr.into_inner()?).context("cannot convert to csv")
}

/// Export as JSON
///
/// # Errors
///
/// This function will return an error on serialization failure
pub fn to_json(vt: &ValuesTable) -> Result<String> {
    let r = serde_json::to_string_pretty(&vt).context("could not convert to json")?;
    Ok(format!("{}\n", r))
}

/// Returns an ASCII drawn table
///
/// # Errors
///
/// This function is not expected to error, just conforms to an interface
#[allow(clippy::missing_panics_doc)]
pub fn to_table(vt: &ValuesTable) -> Result<String> {
    let mut builder = tabled::builder::Builder::default();

    builder.set_columns(&vt.columns);
    for row in &vt.rows {
        builder.add_record(row.iter().map(repr));
    }

    let mut table = builder.build();

    if env::var("CI").is_ok() {
        table.with(tabled::Style::empty());
        Ok(Regex::new(r#"[ ]+"#)
            .unwrap()
            .replace_all(&format!("{}\n", table), " ")
            .to_string())
    } else {
        table.with(tabled::Style::modern());
        Ok(format!("{}\n", table))
    }
}

/// Convert to a xargs-friendly format (a newline separated list of values)
///
/// # Errors
///
/// This function is not expected to error, just conforms to an interface
pub fn to_xargs(vt: &ValuesTable) -> Result<String> {
    Ok(format!(
        "{}\n",
        vt.rows
            .iter()
            .map(|f| f.first().map(repr).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n")
    ))
}
