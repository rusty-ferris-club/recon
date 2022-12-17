#![allow(clippy::struct_excessive_bools)]
use crate::config::ComputedFields;
use crate::{config::Config, data};
use anyhow::{Context, Result};
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use sqlx::{Pool, Sqlite};
use std::fs;
use std::path::Path;
use std::time::Duration;
use tracing::info;

/// Holds options and configuration for a recon run
pub struct RunOptions {
    pub root: Option<String>,
    pub config: Option<String>,
    pub db_url: Option<String>,
    pub db_file: String,
    pub pre_delete: bool,
    pub update: bool,
    pub all_files: bool,
    pub no_spinner: bool,
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
    let first_run = !Path::new(&opts.db_file).exists() || opts.db_file == ":memory:";

    let pool = data::connect(&db_url).await.context("cannot open DB")?;

    let source = &config.source;

    let unpack = source.unpack.unwrap_or(false);

    info!("db: {}", db_url);

    //
    // prefill stage -----------
    //
    if first_run {
        info!("updating data. first run.",);
        data::clear(&pool).await?;
        let s = spin(opts.no_spinner);
        walk_and_store(
            root,
            &source.default_fields(),
            unpack,
            false,
            opts.all_files,
            &s,
            &pool,
        )
        .await?;
        s.finish_and_clear();
    } else if opts.update {
        let s = spin(opts.no_spinner);
        walk_and_store(
            root,
            &source.default_fields(),
            unpack,
            true,
            opts.all_files,
            &s,
            &pool,
        )
        .await?;
        s.finish_and_clear();
    }

    //
    // query stage -----------
    //
    if first_run || opts.update {
        let res: Vec<data::File> = data::query_files(&source.query(), &pool).await?;
        let s = spin(opts.no_spinner);
        data::compute_fields_and_store(&res[..], &source.computed_fields(), &s, &pool).await?;
        s.finish_and_clear();
    }

    let default_query = "select * from files".to_string();
    let query = config
        .source
        .query
        .as_ref()
        .or(opts.query.as_ref())
        .unwrap_or(&default_query);

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
    unpack: bool,
    resume: bool,
    all_files: bool,
    s: &ProgressBar,
    pool: &Pool<Sqlite>,
) -> anyhow::Result<()> {
    let mut count = 0;
    let mut conn = pool.acquire().await?;
    for entry in WalkBuilder::new(path)
        .git_ignore(!all_files) // user asked to walk all files. disable gitignore consideration
        //.ignore(!all_files) // actually, we leave an escape hatch: .ignore. nobody really uses this ordinarily so leave it on.
        .hidden(false) // always look at hidden files
        .build()
    {
        let entry = entry.context("cannot list entry")?;
        if entry.path().is_file() {
            let mut f = data::File::from_entry(&entry)?;
            if resume && data::exists(&f, &mut conn).await? {
                s.set_message(format!("{} files (cached)", count));
            } else {
                s.set_message(format!("{} files", count));
                f = f.process_fields(fields)?;
                
                let is_archive = f.is_archive.unwrap_or(false);
                if unpack && is_archive {
                    f.unpack()?;
                }

                data::insert_one(&f, &mut conn).await?;
            }
            count += 1;
        }
    }
    Ok(())
}

fn spin(no_spinner: bool) -> ProgressBar {
    let pb = if no_spinner {
        ProgressBar::hidden()
    } else {
        ProgressBar::new_spinner()
    };

    pb.set_style(ProgressStyle::with_template("{spinner} [{elapsed_precise}] {msg}").unwrap());
    pb.enable_steady_tick(Duration::from_millis(120));
    pb.set_message("Processing...");
    pb
}
