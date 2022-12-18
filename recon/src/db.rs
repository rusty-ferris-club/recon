use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use serde_json::json;
use sqlx::{
    pool::PoolConnection,
    sqlite::{SqliteColumn, SqliteRow},
    Column, Pool, Row, Sqlite, SqlitePool, TypeInfo, Value, ValueRef,
};
use sqlx_meta::{Binds, Schema};

use crate::data::{File, ValuesTable};

lazy_static! {
    static ref INSERT_SQL: String = {
        let cols = &File::columns()[1..];

        let holders = (0..cols.len()).map(|_| "?").collect::<Vec<_>>().join(", ");

        let excludes = cols
            .iter()
            .map(|c| format!("'{}'=excluded.'{}'", c, c))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            r#"INSERT INTO files
        ({}) 
        VALUES 
        ({})
        ON CONFLICT(abs_path) DO UPDATE SET 
        {}
        "#,
            cols.iter()
                .map(|c| format!("'{}'", c))
                .collect::<Vec<_>>()
                .join(","),
            holders,
            excludes
        )
    };
}

pub struct Db {
    pool: Pool<Sqlite>,
}

impl Db {
    /// Connect to a adb
    ///
    /// # Errors
    ///
    /// This function will return an error if I/O error happened
    pub async fn connect(db_url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(db_url)
            .await
            .context("cannot connect")?;
        sqlx::migrate!()
            .run(&pool)
            .await
            .context("cannot run migrations")?; // embeds ./migrations
        Ok(Self { pool })
    }

    #[tracing::instrument(level = "trace", skip_all, err)]
    pub async fn clear(&self) -> anyhow::Result<()> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query(
            r#"
        DELETE from files
      "#,
        )
        .execute(&mut conn)
        .await?;
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip_all, err)]
    pub async fn exists(&self, f: &File) -> anyhow::Result<bool> {
        let mut conn = self.pool.acquire().await?;

        let total_rows: u32 = sqlx::query_scalar("select count(*) from files where abs_path=?")
            .bind(&f.abs_path)
            .fetch_one(&mut conn)
            .await?;
        Ok(total_rows != 0)
    }

    #[tracing::instrument(level = "trace", skip_all, err)]
    pub(crate) async fn insert_one(&self, f: &File) -> anyhow::Result<()> {
        let mut conn = self.pool.acquire().await?;
        let q = sqlx::query_as::<_, File>(&INSERT_SQL);
        f.update_binds(q).fetch_optional(&mut conn).await?;
        Ok(())
    }

    /// Query into a `Vec` of files, materialized, for dealing with native `File`s.
    ///
    /// # Errors
    ///
    /// This function will return an error on db failure
    #[tracing::instrument(level = "trace", skip_all, err)]
    pub(crate) async fn query_files(&self, q: &str) -> anyhow::Result<Vec<File>> {
        let res = sqlx::query_as::<_, File>(q).fetch_all(&self.pool).await;
        res.context("error while performing query")
    }

    #[tracing::instrument(level = "trace", skip_all, err)]
    pub(crate) async fn query_table(&self, q: &str) -> anyhow::Result<ValuesTable> {
        let res = sqlx::query(q).fetch_all(&self.pool).await?;
        let total_rows: u32 = sqlx::query_scalar("select count(*) from files")
            .fetch_one(&self.pool)
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

    /// Gives out an opaque holder of a connection
    ///
    /// # Errors
    ///
    /// This function will return an error if .
    pub async fn acquire(&self) -> Result<Connection> {
        let connection = self.pool.acquire().await?;
        Ok(Connection { connection })
    }
}

pub struct Connection {
    pub connection: PoolConnection<Sqlite>,
}

/// Represent a col as a string
///
/// # Panics
///
/// Panics if types are wrong/missed
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
