mod cli;
mod config;
mod faketls;
mod obfuscated2;
mod proxy;
mod safety;
mod secret;
mod telegram;
mod tokio_utils;

fn main() {
    cli::Cli::run().unwrap();
}
