use clap::{Parser, Subcommand};

use crate::{config::Config, proxy::Proxy, secret};

#[derive(Clone, Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    #[arg(short, long, default_value = "0")]
    verbose: u8,

    #[arg(short, long, default_value = "config.toml")]
    config_file: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clone, Debug, Subcommand)]
enum Commands {
    CreateSecret {
        #[arg()]
        host: String,
    },
    PrintConfig,
    RunProxy,
}

impl Cli {
    #[cfg(test)]
    pub fn new(verbose: u8) -> Self {
        Self {
            verbose,
            config_file: String::new(),
            command: None,
        }
    }

    pub fn log(&self, level: u8, message: String) {
        if self.verbose >= level {
            println!("{}", message);
        }
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::parse();
        cli.log(3, format!("Params: {:?}", cli));

        let config = Config::load(&cli.config_file);
        cli.log(3, format!("Config: {:?}", config));

        // Run appropriate command
        match &cli.command {
            Some(Commands::CreateSecret { host }) => {
                let secret = secret::MTProtoSecret::new(host);
                println!("Generated secret: {}", secret.to_string());
            }
            Some(Commands::PrintConfig) => {
                toml::to_string_pretty(&config).map(|s| println!("{}", s))?;
            }
            Some(Commands::RunProxy) => {
                Proxy::new(cli, config).run_loop();
            }
            None => {
                toml::to_string_pretty(&config).map(|s| println!("{}", s))?;
                Proxy::new(cli, config).run_loop();
            }
        }
        Ok(())
    }
}
