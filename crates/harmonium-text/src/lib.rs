//! Text encryption/decryption over Discord using `age`.

/// Errors from the harmonium-text crate.
#[derive(Debug, thiserror::Error)]
pub enum TextError {
    #[error("invalid recipient: {0}")]
    InvalidRecipient(String),

    #[error("encryption failed: {0}")]
    Encrypt(#[from] age::EncryptError),

    #[error("decryption failed: {0}")]
    Decrypt(#[from] age::DecryptError),

    #[error("no age armor block found in input")]
    NoArmor,

    #[error("decrypted plaintext is not valid UTF-8")]
    NonUtf8,

    #[error("clipboard error: {0}")]
    Clipboard(#[from] arboard::Error),
}

const ARMOR_BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";
const ARMOR_END: &str = "-----END AGE ENCRYPTED FILE-----";

/// Encrypts `plaintext` to `recipient`, returning ASCII-armored ciphertext.
pub fn encrypt(recipient: &str, plaintext: &str) -> Result<String, TextError> {
    let recipient = recipient
        .parse::<age::x25519::Recipient>()
        .map_err(|e| TextError::InvalidRecipient(e.to_string()))?;
    Ok(age::encrypt_and_armor(&recipient, plaintext.as_bytes())?)
}

/// Decrypts the first age armor block found anywhere in `text`.
///
/// Discord adds surrounding prose and code fences, so the block is located by
/// scanning for the `BEGIN` and `END` markers rather than assuming `text` is
/// exactly one armor block.
pub fn decrypt(identity: &age::x25519::Identity, text: &str) -> Result<String, TextError> {
    let begin = text.find(ARMOR_BEGIN).ok_or(TextError::NoArmor)?;
    let after_begin = &text[begin + ARMOR_BEGIN.len()..];
    let end_rel = after_begin.find(ARMOR_END).ok_or(TextError::NoArmor)?;
    let end = begin + ARMOR_BEGIN.len() + end_rel;

    let mut block_end = end + ARMOR_END.len();
    if text[block_end..].starts_with("\r\n") {
        block_end += 2;
    } else if text[block_end..].starts_with('\n') {
        block_end += 1;
    }
    let block = &text[begin..block_end];

    let plaintext = age::decrypt(identity, block.as_bytes())?;
    String::from_utf8(plaintext).map_err(|_| TextError::NonUtf8)
}

/// Whether `armored` fits within Discord's 2000-character message limit.
pub fn fits_discord(armored: &str) -> bool {
    armored.chars().count() <= 2000
}

/// Encrypts the current clipboard contents to `recipient` and replaces them.
pub fn clipboard_encrypt(recipient: &str) -> Result<String, TextError> {
    let mut clipboard = arboard::Clipboard::new()?;
    let text = clipboard.get_text()?;
    let armored = encrypt(recipient, &text)?;
    clipboard.set_text(armored.as_str())?;
    Ok(armored)
}

/// Decrypts the current clipboard contents with `identity` and returns the plaintext.
///
/// The clipboard is left untouched: writing plaintext there would leave it in clipboard
/// managers' history (Klipper, Windows clipboard history) long after the message is read.
pub fn clipboard_decrypt(identity: &age::x25519::Identity) -> Result<String, TextError> {
    let text = arboard::Clipboard::new()?.get_text()?;
    decrypt(identity, &text)
}
