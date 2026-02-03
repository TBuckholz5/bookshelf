use std::error::Error;

pub enum SourceFile {
    Author,
    Work,
    Edition,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Hello, world!");
    Ok(())
}
