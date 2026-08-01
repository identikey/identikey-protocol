//! `ikey` — IdentiKey identity wallet CLI.
//!
//! Manages a password-encrypted wallet of cryptographic identities
//! (Ed25519 + optional ML-DSA-87), usable by any IdentiKey application.

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use identikey_wallet::{
    default_provider_for, BasicIdentity, KeyPair, Wallet, WalletIdentity as _,
};

type IkeyWallet = Wallet<BasicIdentity>;

#[derive(Parser)]
#[command(name = "ikey", version, about = "IdentiKey identity wallet")]
struct Cli {
    /// Wallet file path (default: platform data dir)
    #[arg(long, global = true, env = "IDENTIKEY_WALLET")]
    wallet: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage identities in the wallet
    #[command(subcommand)]
    Identity(IdentityCommand),
    /// Manage the wallet itself (lock/unlock/status)
    #[command(subcommand)]
    Wallet(WalletCommand),
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Create a new identity
    New {
        /// Identity name
        #[arg(long, default_value = "default")]
        name: String,
        /// Skip the ML-DSA-87 post-quantum keypair (Ed25519 only)
        #[arg(long)]
        no_pq: bool,
    },
    /// List identities
    List,
    /// Show an identity (public material only)
    Show {
        /// Identity name (default: active identity)
        name: Option<String>,
    },
    /// Set the active identity
    Use { name: String },
    /// Delete an identity
    Delete { name: String },
}

#[derive(Subcommand)]
enum WalletCommand {
    /// Unlock the wallet (prompt for password, cache the key)
    Unlock,
    /// Lock the wallet (clear the cached key)
    Lock,
    /// Show wallet status
    Status,
    /// Print the wallet file path
    Path,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Identity(cmd) => identity_command(cmd, cli.wallet.as_deref()),
        Command::Wallet(cmd) => wallet_command(cmd, cli.wallet.as_deref()),
    }
}

fn identity_command(cmd: IdentityCommand, wallet_path: Option<&str>) -> Result<()> {
    match cmd {
        IdentityCommand::New { name, no_pq } => {
            let mut wallet = IkeyWallet::load(wallet_path)?;
            if wallet.data.identities.contains_key(&name) {
                bail!("Identity '{name}' already exists");
            }
            let is_new = wallet.is_new();

            let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
            let created_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let mut identity = BasicIdentity::new(
                created_at,
                sk.verifying_key().to_bytes().to_vec(),
                sk.to_bytes().to_vec(),
            );

            if !no_pq {
                use fips204::traits::SerDes;
                let (pk, sk) = fips204::ml_dsa_87::try_keygen()
                    .map_err(|e| anyhow!("ml-dsa-87 keygen: {e}"))?;
                identity.ml_dsa = Some(KeyPair {
                    public: pk.into_bytes().to_vec(),
                    secret: sk.into_bytes().to_vec(),
                });
            }

            let fingerprint = identity.fingerprint_b58();
            wallet.data.identities.insert(name.clone(), identity);
            if wallet.data.active_identity.is_none() {
                wallet.data.active_identity = Some(name.clone());
            }
            wallet.save(is_new)?;
            println!("Created identity '{name}'");
            println!("Fingerprint: {fingerprint}");
            Ok(())
        }
        IdentityCommand::List => {
            let wallet = IkeyWallet::load(wallet_path)?;
            if wallet.data.identities.is_empty() {
                println!("No identities. Create one with `ikey identity new`.");
                return Ok(());
            }
            let mut names: Vec<&String> = wallet.data.identities.keys().collect();
            names.sort();
            for name in names {
                let id = &wallet.data.identities[name];
                let active = if wallet.data.active_identity.as_deref() == Some(name) {
                    " (active)"
                } else {
                    ""
                };
                let pq = if id.ml_dsa.is_some() { "+pq" } else { "" };
                println!("{name}{active}  {} {pq}", id.fingerprint_b58());
            }
            Ok(())
        }
        IdentityCommand::Show { name } => {
            let wallet = IkeyWallet::load(wallet_path)?;
            let name = match name.or_else(|| wallet.data.active_identity.clone()) {
                Some(n) => n,
                None => bail!("No identity specified and no active identity set"),
            };
            let id = wallet
                .data
                .identities
                .get(&name)
                .ok_or_else(|| anyhow!("Identity '{name}' not found"))?;
            println!("Name:        {name}");
            println!("Fingerprint: {}", id.fingerprint_b58());
            println!("Created:     {} (epoch seconds)", id.created_at);
            println!("Ed25519:     {} byte public key", id.ed25519.public.len());
            match &id.ml_dsa {
                Some(kp) => println!("ML-DSA-87:   {} byte public key", kp.public.len()),
                None => println!("ML-DSA-87:   (none)"),
            }
            Ok(())
        }
        IdentityCommand::Use { name } => {
            let mut wallet = IkeyWallet::load(wallet_path)?;
            if !wallet.data.identities.contains_key(&name) {
                bail!("Identity '{name}' not found");
            }
            wallet.data.active_identity = Some(name.clone());
            wallet.save(false)?;
            println!("Active identity: {name}");
            Ok(())
        }
        IdentityCommand::Delete { name } => {
            let mut wallet = IkeyWallet::load(wallet_path)?;
            if wallet.data.identities.remove(&name).is_none() {
                bail!("Identity '{name}' not found");
            }
            if wallet.data.active_identity.as_deref() == Some(&name) {
                wallet.data.active_identity = None;
            }
            wallet.save(false)?;
            println!("Deleted identity '{name}'");
            Ok(())
        }
    }
}

fn wallet_command(cmd: WalletCommand, wallet_path: Option<&str>) -> Result<()> {
    let path = match wallet_path {
        Some(p) => std::path::PathBuf::from(p),
        None => IkeyWallet::default_path()?,
    };
    let params = BasicIdentity::PARAMS;
    match cmd {
        WalletCommand::Unlock => {
            // Loading with the default provider prompts and caches the key.
            let wallet = IkeyWallet::load(wallet_path)?;
            if wallet.is_new() {
                println!("Wallet is empty; nothing to unlock. Create an identity first.");
            } else {
                println!("Wallet unlocked (key cached).");
            }
            Ok(())
        }
        WalletCommand::Lock => {
            let provider = default_provider_for(&path, params);
            provider.clear_key()?;
            println!("Wallet locked (cached key cleared from {}).", provider.name());
            Ok(())
        }
        WalletCommand::Status => {
            let provider = default_provider_for(&path, params);
            let cached = provider.get_key()?.is_some();
            println!("Wallet:   {}", path.display());
            println!("Exists:   {}", path.exists());
            println!("Provider: {}", provider.name());
            println!("Unlocked: {cached}");
            Ok(())
        }
        WalletCommand::Path => {
            println!("{}", path.display());
            Ok(())
        }
    }
}
