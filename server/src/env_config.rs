use std::env;

use crate::error::AppError;

pub struct EnvConfig {
    pub server_host: String,
    pub server_port: String,
    pub db_host: String,
    pub db_port: String,
    pub db_name: String,
    pub db_password: String,
    pub db_user: String,
    pub db_sslmode: String,
}

impl EnvConfig {
    pub fn load() -> Result<Self, AppError> {
        dotenv::dotenv()?;
        let server_host = env::var("SERVER_HOST")?;
        let server_port = env::var("SERVER_PORT")?;
        let db_host = env::var("DATABASE_HOST")?;
        let db_port = env::var("DATABASE_PORT")?;
        let db_name = env::var("DATABASE_NAME")?;
        let db_password = env::var("DATABASE_PASSWORD")?;
        let db_sslmode = env::var("DATABASE_SSLMODE")?;
        let db_user = env::var("DATABASE_USER")?;
        Ok(Self {
            server_host,
            server_port,
            db_host,
            db_port,
            db_name,
            db_password,
            db_sslmode,
            db_user,
        })
    }
}
