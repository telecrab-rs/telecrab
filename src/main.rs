mod cli;
mod config;
mod faketls;
mod obfuscated2;
mod proxy;
mod safety;
mod secret;

fn main() {
    cli::Cli::run().unwrap();
}
