use std::error::Error;

use axum::{Router, routing::get};
use sqlx::postgres::PgPoolOptions;

use crate::env_config::EnvConfig;

mod env_config;
mod error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Read configuration from environment variables and .env file.
    let env_config = EnvConfig::load()?;

    // Connect to DB and run migration.
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&format!(
            "postgresql://{}:{}@{}:{}/{}?sslmode={}",
            env_config.db_user,
            env_config.db_password,
            env_config.db_host,
            env_config.db_port,
            env_config.db_name,
            env_config.db_sslmode
        ))
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    let app = Router::new()
        .route("/", get(handler))
        .route("/{name}", get(hello_name));

    let listener = tokio::net::TcpListener::bind(format!(
        "{}:{}",
        env_config.server_host, env_config.server_port
    ))
    .await
    .unwrap();

    println!("Listening on http://{}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
    Ok(())
}

async fn handler() -> &'static str {
    "Hello, World!"
}

async fn hello_name(axum::extract::Path(name): axum::extract::Path<String>) -> String {
    format!("Hello, {name}!")
}
