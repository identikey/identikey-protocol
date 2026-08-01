//! Wallet file management with credential provider integration.

use anyhow::{Context as _, Result};
use dialoguer::Password;
use directories::ProjectDirs;
use rand::RngCore;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroize;

use super::credential::{default_provider_for, CredentialProvider};
use super::envelope::WalletIdentity;
use super::format::{
    decrypt_wallet_with_key, derive_key, encrypt_wallet_with_key, extract_salt, WalletData,
};

/// Get password from env var or interactive prompt
fn get_password(prompt: &str, env_var: &str) -> Result<String> {
    if let Ok(password) = std::env::var(env_var) {
        return Ok(password);
    }
    Ok(Password::new().with_prompt(prompt).interact()?)
}

/// Get password with confirmation from env var or interactive prompts
fn get_password_with_confirm(env_var: &str) -> Result<String> {
    if let Ok(password) = std::env::var(env_var) {
        return Ok(password);
    }

    let pass1 = Password::new()
        .with_prompt("New wallet password")
        .interact()?;
    let pass2 = Password::new().with_prompt("Confirm password").interact()?;

    if pass1 != pass2 {
        anyhow::bail!("Passwords do not match");
    }

    Ok(pass1)
}

pub struct Wallet<I: WalletIdentity> {
    pub data: WalletData<I>,
    path: PathBuf,
    key: [u8; 32],
    salt: [u8; 32],
}

impl<I: WalletIdentity> Drop for Wallet<I> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl<I: WalletIdentity> Wallet<I> {
    /// Load wallet, using cached key from provider or prompting for password
    pub fn load(override_path: Option<&str>) -> Result<Self> {
        let path = Self::resolve_path(override_path)?;
        let provider = default_provider_for(&path, I::PARAMS);
        Self::load_with_provider(override_path, provider.as_ref())
    }

    /// Load wallet with explicit credential provider (for testing)
    pub fn load_with_provider(
        override_path: Option<&str>,
        provider: &dyn CredentialProvider,
    ) -> Result<Self> {
        let path = Self::resolve_path(override_path)?;

        if !path.exists() {
            // New wallet: generate fresh salt, key will be set on first save
            let mut salt = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut salt);
            return Ok(Self {
                data: WalletData::new(),
                path,
                key: [0u8; 32], // Placeholder, will be set on save
                salt,
            });
        }

        let encrypted = fs::read(&path)
            .with_context(|| format!("Failed to read wallet from {}", path.display()))?;

        let salt = extract_salt(&encrypted, I::PARAMS)?;

        // Try cached key from provider first
        if let Ok(Some(key)) = provider.get_key() {
            if let Ok(data) = decrypt_wallet_with_key(&encrypted, &key, I::PARAMS) {
                return Ok(Self {
                    data,
                    path,
                    key,
                    salt,
                });
            }
            // Cached key didn't work (different wallet?), fall through to password prompt
        }

        // No cached key or it was invalid, get password from env or prompt
        let password = get_password("Wallet password", I::PARAMS.env_password)?;
        let key = derive_key(&password, &salt)?;
        let data = decrypt_wallet_with_key(&encrypted, &key, I::PARAMS)
            .context("Failed to decrypt wallet (wrong password?)")?;

        // Cache the derived key for next time
        if let Err(e) = provider.store_key(&key) {
            eprintln!("Warning: couldn't cache key in {}: {e}", provider.name());
        }

        Ok(Self {
            data,
            path,
            key,
            salt,
        })
    }

    /// Save wallet to disk
    pub fn save(&mut self, is_new: bool) -> Result<()> {
        let provider = default_provider_for(&self.path, I::PARAMS);
        self.save_with_provider(is_new, provider.as_ref())
    }

    /// Save wallet with explicit provider (for testing)
    pub fn save_with_provider(
        &mut self,
        is_new: bool,
        provider: &dyn CredentialProvider,
    ) -> Result<()> {
        let (key, salt) = if is_new {
            // New wallet: get password from env or prompt with confirmation
            let password = get_password_with_confirm(I::PARAMS.env_password)?;

            let mut salt = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut salt);
            let key = derive_key(&password, &salt)?;

            // Update self with new key/salt
            self.key = key;
            self.salt = salt;

            // Cache for future use
            if let Err(e) = provider.store_key(&key) {
                eprintln!("Warning: couldn't cache key in {}: {e}", provider.name());
            }

            (key, salt)
        } else {
            // Existing wallet: use cached key (should have been set during load)
            (self.key, self.salt)
        };

        let encrypted = encrypt_wallet_with_key(&self.data, &key, &salt, I::PARAMS)?;

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        write_secret_file(&self.path, &encrypted)
            .with_context(|| format!("Failed to write wallet to {}", self.path.display()))?;

        Ok(())
    }

    fn resolve_path(override_path: Option<&str>) -> Result<PathBuf> {
        match override_path {
            Some(p) => Ok(PathBuf::from(p)),
            None => Self::default_path(),
        }
    }

    /// Platform-specific default wallet path, per `WalletParams`:
    ///   macOS:   ~/Library/Application Support/<qual>.<org>.<app>/
    ///   Linux:   ~/.local/share/<app>/
    ///   Windows: C:\Users\<user>\AppData\Roaming\<org>\<app>\
    pub fn default_path() -> Result<PathBuf> {
        let p = I::PARAMS;
        let dirs = ProjectDirs::from(p.dir_qualifier, p.dir_organization, p.dir_application)
            .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
        Ok(dirs.data_dir().join(p.wallet_file_name))
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn is_new(&self) -> bool {
        self.data.identities.is_empty()
    }

    /// Construct a wallet directly from parts (for tests and migrations).
    pub fn from_parts(data: WalletData<I>, path: PathBuf, key: [u8; 32], salt: [u8; 32]) -> Self {
        Self {
            data,
            path,
            key,
            salt,
        }
    }
}

/// Write a file containing secret material with restrictive permissions.
///
/// On Unix the file is created with mode 0o600 atomically (no read window where
/// the file is world-readable). On other platforms falls back to a plain write
/// — callers should document the lack of OS-level protection there.
pub fn write_secret_file(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    // Atomic write via temp file in the same directory + rename.
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let tmp_path = dir.join(format!(".{}.tmp", file_name.to_string_lossy()));

    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp_path)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }

    fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basic::tests::test_identity;
    use crate::credential::MemoryProvider;
    use crate::{BasicIdentity, IDENTIKEY_PARAMS};
    use tempfile::NamedTempFile;

    fn create_test_wallet() -> (NamedTempFile, [u8; 32], [u8; 32]) {
        let key = [0x42u8; 32];
        let salt = [0x24u8; 32];

        let mut data: WalletData<BasicIdentity> = WalletData::new();
        data.identities
            .insert("test-identity".to_string(), test_identity(0x11));

        let encrypted = encrypt_wallet_with_key(&data, &key, &salt, &IDENTIKEY_PARAMS).unwrap();
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), encrypted).unwrap();

        (file, key, salt)
    }

    #[test]
    fn test_load_with_cached_key() {
        let (file, key, _salt) = create_test_wallet();
        let provider = MemoryProvider::with_key(key);

        let wallet: Wallet<BasicIdentity> =
            Wallet::load_with_provider(Some(file.path().to_str().unwrap()), &provider).unwrap();

        assert!(wallet.data.identities.contains_key("test-identity"));
    }

    #[test]
    fn test_load_caches_key_after_decrypt() {
        let (file, _key, salt) = create_test_wallet();

        let password = "test-password";
        let derived_key = derive_key(password, &salt).unwrap();

        // Re-encrypt with password-derived key
        let mut data: WalletData<BasicIdentity> = WalletData::new();
        data.identities
            .insert("test".to_string(), test_identity(0x77));
        let encrypted =
            encrypt_wallet_with_key(&data, &derived_key, &salt, &IDENTIKEY_PARAMS).unwrap();
        std::fs::write(file.path(), encrypted).unwrap();

        let provider_with_key = MemoryProvider::with_key(derived_key);
        let wallet: Wallet<BasicIdentity> =
            Wallet::load_with_provider(Some(file.path().to_str().unwrap()), &provider_with_key)
                .unwrap();

        assert!(wallet.data.identities.contains_key("test"));
    }

    #[test]
    fn test_save_with_provider() {
        let provider = MemoryProvider::with_key([0x42u8; 32]);
        let file = NamedTempFile::new().unwrap();

        let mut wallet: Wallet<BasicIdentity> = Wallet::from_parts(
            WalletData::new(),
            file.path().to_path_buf(),
            [0x42u8; 32],
            [0x24u8; 32],
        );

        wallet
            .data
            .identities
            .insert("new-identity".to_string(), test_identity(0x55));

        // Save without password prompt (not new)
        wallet.save_with_provider(false, &provider).unwrap();

        let reloaded: Wallet<BasicIdentity> =
            Wallet::load_with_provider(Some(file.path().to_str().unwrap()), &provider).unwrap();

        assert!(reloaded.data.identities.contains_key("new-identity"));
    }
}
