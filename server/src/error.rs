use std::env;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Configuration load failed: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Env load failed: {0}")]
    DotEnv(#[from] dotenv::Error),

    #[error("Env load failed: {0}")]
    Env(#[from] env::VarError),

    #[error("Database connection failed: {0}")]
    Database(#[from] sqlx::Error),
}
