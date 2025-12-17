use config::Config;

use crate::error::AppError;

pub struct EnvConfig {
    pub server_host: String,
    pub server_port: i64,
    pub db_host: String,
    pub db_port: i64,
    pub db_name: String,
    pub db_password: String,
    pub db_user: String,
    pub db_sslmode: String,
}

impl EnvConfig {
    pub fn load() -> Result<Self, AppError> {
        let settings = Config::builder()
            .add_source(config::Environment::default())
            .add_source(config::File::with_name(".env"))
            .build()?;
        let server_host = settings.get_string("SERVER_HOST")?;
        let server_port = settings.get_int("SERVER_PORT")?;
        let db_host = settings.get_string("DATABASE_HOST")?;
        let db_port = settings.get_int("DATABASE_PORT")?;
        let db_name = settings.get_string("DATABASE_NAME")?;
        let db_password = settings.get_string("DATABASE_PASSWORD")?;
        let db_sslmode = settings.get_string("DATABASE_SSLMODE")?;
        let db_user = settings.get_string("DATABASE_USER")?;
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
