use std::process;

use clap::Parser;

mod boundaryless;
mod file_signatures;
mod filter;
mod formats;
mod hashes;
mod identifier;
mod input;
mod mac_vendors;
mod mastercard;
mod output;
mod phone_codes;
mod regex_patterns;

use filter::Filter;
use identifier::Match;
use output::OutputOpts;

/// fth — Identify anything. Hashes, keys, credentials, MAC addresses, and more.
///
/// Example usage:
///     fth '5f4dcc3b5aa765d61d8327deb882cf99'
///     fth 'F8:8F:CA:00:11:22'
///     fth --json '5d41402abc4b2a76b9719d911017c592'
///     fth secret.txt
///     fth /path/to/directory
///     Note: Use single quotes ' as inverted commas " do not work well on Linux.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Text to identify, or path to a file/directory to scan.
    text_input: Option<String>,

    /// Output results as JSON.
    #[arg(long = "json")]
    json: bool,

    /// Filter by rarity range (format: min:max, e.g. 0.1:1, 0.5:, :0.8).
    #[arg(short = 'r', long = "rarity", default_value = "0.1:1")]
    rarity: String,

    /// Only include matches with these tags (comma-separated).
    #[arg(short = 'i', long = "include")]
    include: Option<String>,

    /// Exclude matches with these tags (comma-separated).
    #[arg(short = 'e', long = "exclude")]
    exclude: Option<String>,

    /// Treat input as raw text only — do not scan files or directories.
    #[arg(short = 'o', long = "only-text")]
    only_text: bool,

    /// Sort results by key: name, rarity, matched, none.
    #[arg(short = 'k', long = "key")]
    key: Option<String>,

    /// Reverse the sort order.
    #[arg(long = "reverse")]
    reverse: bool,

    /// Show available tags and exit.
    #[arg(short = 't', long = "tags")]
    tags: bool,

    /// Don't print John The Ripper information.
    #[arg(long = "no-john")]
    no_john: bool,

    /// Don't print Hashcat information.
    #[arg(long = "no-hashcat")]
    no_hashcat: bool,

    /// Turn on debugging logs. -vvv for maximum logs.
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,
}

fn sort_matches(matches: &mut [Match], key: Option<&str>, reverse: bool) {
    match key {
        Some("name") => matches.sort_by(|a, b| a.name.cmp(&b.name)),
        Some("matched") => matches.sort_by(|a, b| a.matched_text.cmp(&b.matched_text)),
        Some("rarity") | None => {
            matches.sort_by(|a, b| {
                b.rarity
                    .partial_cmp(&a.rarity)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        Some("none") => {}
        Some(other) => {
            eprintln!(
                "Unknown sort key: '{}'. Valid keys: name, rarity, matched, none",
                other
            );
            process::exit(1);
        }
    }
    if reverse {
        matches.reverse();
    }
}

fn print_tags() {
    let tags = [
        "Credentials",
        "Cryptocurrency",
        "File Signature",
        "Financial",
        "Hash",
        "Network",
        "PGP",
        "Phone",
        "SSH Public Key",
        "URL",
    ];
    for tag in &tags {
        println!("{}", tag);
    }
}

fn main() {
    let args = Args::parse();

    let log_level = match args.verbose {
        0 => "off",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();
    log::debug!("{:?}", args);

    if args.tags {
        print_tags();
        return;
    }

    let text_input = match args.text_input {
        Some(ref t) => t.clone(),
        None => {
            eprintln!("Text input expected. Run 'fth --help' for help.");
            process::exit(1);
        }
    };

    let (rarity_min, rarity_max) = match filter::parse_rarity_range(&args.rarity) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };
    let filter = Filter {
        rarity_min,
        rarity_max,
        include_tags: args
            .include
            .map(|s| s.split(',').map(|t| t.trim().to_string()).collect()),
        exclude_tags: args
            .exclude
            .map(|s| s.split(',').map(|t| t.trim().to_string()).collect()),
    };

    let output_opts = OutputOpts {
        show_john: !args.no_john,
        show_hashcat: !args.no_hashcat,
    };

    let all_ids = identifier::all_identifiers();
    let inputs = input::resolve_input(&text_input, args.only_text);

    for text in &inputs {
        let mut matches: Vec<Match> = all_ids.iter().flat_map(|id| id.identify(text)).collect();

        matches = filter.apply(matches);
        sort_matches(&mut matches, args.key.as_deref(), args.reverse);

        if !matches.is_empty() {
            if !args.json && inputs.len() > 1 {
                println!("{}", text);
                println!("{}", "-".repeat(text.len().min(60)));
            }
            output::print_results(&matches, args.json, &output_opts);
        }
    }
}
