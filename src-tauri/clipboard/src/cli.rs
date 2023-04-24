use std::fmt::{Debug, Display};

use clap::{Parser, Subcommand};

use clipboard::get;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
  #[arg(short, long)]
  format: Option<String>,
  #[command(subcommand)]
  command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
  Get,
  Set {
    #[arg(short = 'c', long = "stdin")]
    from_stdin: bool,
    #[arg(short = 't', long = "type")]
    set_type: Option<String>,
    value: Option<String>,
  },
}

fn error<E: Debug, S: Display>(e: Option<E>, msg: S) {
  eprintln!("{msg}: {e:?}");
  std::process::exit(1);
}

fn main() {
  let cli = Cli::parse();
  match &cli.command {
    None => {}
    Some(Commands::Get) => {
      let c = get()
        .map_err(|e| {
          error(e.into(), "failed to get clipboard");
        })
        .unwrap();
      let data = serde_json::to_string(&c)
        .map_err(|e| {
          error(e.into(), "failed to get clipboard");
        })
        .unwrap();
      println!("{data}");
    }
    Some(Commands::Set {
      from_stdin,
      value,
      set_type,
    }) => {
      if *from_stdin {
        let mut stream = serde_json::Deserializer::from_reader(std::io::stdin()).into_iter();
        match stream.next() {
          Some(Ok(c)) => {
            clipboard::set(c)
              .map_err(|e| {
                error(e.into(), "failed to set clipboard");
              })
              .unwrap_or(());
          }
          Some(Err(e)) => error(e.into(), "failed to get clipboard"),
          None => error("".into(), "parse stdin failed"),
        }
      } else {
        if value.is_none() {
          error("".into(), "value is None");
        }
        let content_type = set_type.clone().unwrap_or("string".into());
        match content_type.as_str() {
          "string" | "s" | "str" => {
            clipboard::set(clipboard::Content::String(value.clone().unwrap())).unwrap()
          }
          _ => error("".into(), "not support content type"),
        }
      }
    }
  }
}
