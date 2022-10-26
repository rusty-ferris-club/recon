use crate::config::ComputedFields;
use crate::{config::Config, data};
use anyhow::{Context, Result};
use sqlx::{Acquire, Pool, Sqlite};
use std::fs;
use std::path::Path;
use tracing::info;
use walkdir::WalkDir;

/// Holds options and configuration for a recon run
pub struct RunOptions {
    pub root: Option<String>,
    pub config: Option<String>,
    pub db_url: Option<String>,
    pub db_file: String,
    pub pre_delete: bool,
    pub update: bool,
    pub query: Option<String>,
}

/// Run a recon workflow with given options
///
/// # Errors
///
/// This function will return an error if db, I/O or processing failures occcured
pub async fn run(opts: &RunOptions) -> Result<data::ValuesTable> {
    let config = opts
        .config
        .as_ref()
        .map_or_else(
            || Ok(Config::default()),
            |c| Config::from_path(Path::new(&c)),
        )
        .context("cannot load configuration")?;
    let default_root = ".".to_string();
    let root = opts
        .root
        .as_ref()
        .or(config.source.root.as_ref())
        .unwrap_or(&default_root);
    // file or url handling
    // if they give us a complete URL, that wins over all.
    let db_url = opts.db_url.as_ref().map_or_else(
        || {
            // otherwise, get a default file name, and handle a pre-run delete
            let file = &opts.db_file;
            if opts.pre_delete {
                info!("removing existing db");
                let _res = fs::remove_file(file);
            }
            format!("sqlite:{}?mode=rwc", file)
        },
        Clone::clone,
    );
    let first_run = !Path::new(&opts.db_file).exists();

    let pool = data::connect(&db_url).await.context("cannot open DB")?;

    let source = &config.source;

    info!("db: {}", db_url);
    //
    // prefill stage -----------
    //
    if first_run || opts.update {
        info!(
            "updating data. first run: {}, update requested: {}",
            first_run, opts.update
        );
        data::clear(&pool).await?;
        walk_and_store(root, &source.default_fields(), &pool).await?;
    }
    let res: Vec<data::File> = data::query_files(&source.query(), &pool).await?;

    //
    // query stage -----------
    //
    let default_query = "select * from files".to_string();
    let query = config
        .source
        .query
        .as_ref()
        .or(opts.query.as_ref())
        .unwrap_or(&default_query);
    data::compute_fields_and_store(&res[..], &source.computed_fields(), &pool).await?;
    data::query(query, &pool).await
}

/// For a given path, walk a directory tree, and for each file
/// fill in computed fields.
/// Lastly, store results in DB.
/// Later, you can query results back to get a vector of `File`s.
///
/// # Errors
///
/// This function will return an error on folder walking I/O failure, data processing, or database access failure
#[tracing::instrument(level = "trace", skip_all, err)]
async fn walk_and_store(
    path: &str,
    fields: &ComputedFields,
    pool: &Pool<Sqlite>,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    let mut txn = conn.begin().await.context("cannot get tx")?;
    for entry in WalkDir::new(path) {
        let entry = entry.context("cannot list entry")?;
        if entry.path().is_file() {
            // before_query
            let f = data::File::from_entry(&entry)?.process_fields(fields)?;
            data::insert_one(&f, &mut txn).await?;
        }
    }
    txn.commit().await.context("cannot commit txn")?;
    Ok(())
}
