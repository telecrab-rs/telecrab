mod cli;
mod config;
mod faketls;
mod obfuscated2;
mod proxy;
mod safety;
mod secret;
mod telegram;

fn main() {
    cli::Cli::run().unwrap();
}
