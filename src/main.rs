mod cli;
mod config;
mod faketls;
mod proxy;
mod secret;

fn main() {
    cli::Cli::run().unwrap();
}
