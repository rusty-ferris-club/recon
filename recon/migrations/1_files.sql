CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY,
  entry_time DATETIME,
  abs_path VARCHAR UNIQUE,

  path VARCHAR NOT NULL,
  ext VARCHAR,
  mode VARCHAR,

  is_dir boolean,
  is_file boolean,
  is_symlink boolean,
  is_empty boolean,
  is_binary boolean,

  size BIGINT,

  user VARCHAR,
  'group' VARCHAR,
  uid INT,
  gid INT,

  atime DATETIME,
  mtime DATETIME,
  ctime DATETIME,
  
  is_archive boolean,
  is_document boolean,
  is_media boolean,
  is_code boolean,
  is_ignored boolean,

  bytes_type VARCHAR,
  file_magic VARCHAR,
  crc32 VARCHAR,
  sha256 VARCHAR,
  sha512 VARCHAR,
  md5 VARCHAR,
  simhash VARCHAR,

  crc32_match JSON,
  sha256_match JSON,
  sha512_match JSON,
  md5_match JSON,
  simhash_match JSON,
  path_match JSON,
  content_match JSON,
  yara_match JSON,
  
  computed boolean
);

CREATE UNIQUE INDEX idx_abs_path 
ON files (abs_path);
