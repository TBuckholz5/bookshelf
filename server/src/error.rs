use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Configuration load failed: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Database connection failed: {0}")]
    Database(#[from] sqlx::Error),
}
