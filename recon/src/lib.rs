#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
//#![deny(missing_docs)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::uninlined_format_args)]
pub use data::DB_FILE;

pub mod config;
pub mod data;
pub mod db;
mod matching;
pub mod os;
pub mod out;
mod processing;
pub mod workflow;
