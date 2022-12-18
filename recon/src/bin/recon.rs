#![allow(clippy::must_use_candidate)]
use clap::crate_version;
use clap::ArgAction;
use recon::workflow;
use recon::workflow::RunOptions;
use std::env;
use std::time::Instant;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{filter, EnvFilter, Registry};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use anyhow::Result;
use clap::{Arg, Command};
use std::process::exit;

#[allow(clippy::too_many_lines)]
pub fn command() -> Command {
    Command::new("recon")
        .version(crate_version!())
        .about("SQL over files with security processing and tests")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("CONFIG_FILE")
                .help("Point to a configuration"),
        )
        .arg(
            Arg::new("root")
                .short('r')
                .long("root")
                .value_name("ROOT")
                .help("Target folder to scan"),
        )
        .arg(
            Arg::new("query")
                .short('q')
                .long("query")
                .value_name("SQL")
                .help("Query with SQL"),
        )
        .arg(
            Arg::new("file")
                .short('f')
                .long("file")
                .value_name("DB_FILE")
                .default_value(recon::DB_FILE)
                .help("Use a specific DB file (file or :memory: for in memory)"),
        )
        .arg(
            Arg::new("delete")
                .short('d')
                .long("delete")
                .action(ArgAction::SetTrue)
                .help("Clear data: delete existing cache database before running"),
        )
        .arg(
            Arg::new("update")
                .short('u')
                .long("update")
                .action(ArgAction::SetTrue)
                .help("Always walk files and update DB before query. Leave off to run query on existing recon.db."),
        )
        .arg(
            Arg::new("all")
                .short('a')
                .long("all")
                .help("Walk all files (dont consider .gitignore)")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-progress")
                .long("no-progress")
                .help("Don't display progress bars")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("inmem")
                .short('m')
                .long("inmem")
                .help("Don't cache index to disk, run in-memory only")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("xargs")
                .long("xargs")
                .help("Output as xargs formatted list")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .help("Output as JSON")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("csv")
                .long("csv")
                .help("Output as CSV")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-style")
                .long("no-style")
                .help("Output as a table with no styles")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("fail-some")
                .long("fail-some")
                .help("Exit code failure if *some* files are found")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("fail-none")
                .long("fail-none")
                .help("Exit code failure if *no* files are found")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .help("Show logs")
                .action(ArgAction::SetTrue),
        )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    let app = command();
    let matches = app.clone().get_matches();

    let level = if matches.get_flag("verbose") {
        LevelFilter::INFO
    } else {
        LevelFilter::OFF
    };

    Registry::default()
        .with(tracing_tree::HierarchicalLayer::new(2))
        .with(
            filter::Targets::new()
                .with_target("sqlx::query", filter::LevelFilter::OFF)
                .with_target("users::base", filter::LevelFilter::OFF)
                .with_default(level),
        )
        .with(
            EnvFilter::builder()
                .with_default_directive(level.into())
                .with_env_var("LOG")
                .from_env_lossy(),
        )
        .init();

    let opts = RunOptions {
        root: matches.get_one::<String>("root").cloned(),
        config: matches.get_one::<String>("config").cloned(),
        pre_delete: matches.get_flag("delete"),
        db_url: env::var("DATABASE_URL").ok(),
        db_file: if matches.get_flag("inmem") {
            ":memory:".to_string()
        } else {
            matches
                .get_one::<String>("file")
                .cloned()
                .expect("should have default set")
        },
        update: matches.get_flag("update"),
        all_files: matches.get_flag("all"),
        no_spinner: matches.get_flag("no-progress"),
        query: matches.get_one::<String>("query").cloned(),
    };

    let res: Result<bool> = match matches.subcommand() {
        None => {
            let t = Instant::now();

            let vt = workflow::run(&opts).await?;

            let (with_summary, out) = if matches.get_flag("csv") {
                (false, vt.to_csv()?)
            } else if matches.get_flag("json") {
                (false, vt.to_json()?)
            } else if matches.get_flag("xargs") {
                (false, vt.to_xargs()?)
            } else {
                (true, vt.to_table()?)
            };
            print!("{out}");

            let len = vt.rows.len();
            if with_summary {
                eprintln!("{len} of {} files in {:?}", vt.total_rows, t.elapsed());
            }

            // note: negative-positive logic below
            let computed_success = if matches.get_flag("fail-some") {
                len == 0
            } else if matches.get_flag("fail-none") {
                len != 0
            } else {
                true
            };
            Ok(computed_success)
        }
        _ => Ok(false),
    };

    match res {
        Ok(ok) => {
            exit(i32::from(!ok));
        }
        Err(err) => {
            eprintln!("error: {err}");
            exit(1)
        }
    }
}
