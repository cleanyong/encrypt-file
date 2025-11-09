use aes::Aes256;
use cbc::{
    cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit},
    Encryptor,
};
use clap::Parser;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process;

#[derive(Parser, Debug)]
#[command(
    name = "encrypt-file",
    about = "AES-256-CBC encrypt a file. Output = IV || ciphertext saved as <input>.enc",
    disable_help_subcommand = true
)]
struct Args {
    /// Password used to derive the AES-256 key (SHA-256(password)).
    #[arg(value_name = "PASSWORD")]
    password: String,

    /// Path to the plaintext file to encrypt.
    #[arg(value_name = "FILE")]
    input: PathBuf,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let key = derive_key_from_password(&args.password);
    let iv = generate_random_iv();
    let output = derive_output_path(&args.input)?;

    let plaintext = fs::read(&args.input)
        .map_err(|err| format!("failed to read input file {:?}: {err}", args.input))?;

    let cipher = Encryptor::<Aes256>::new_from_slices(&key, &iv)
        .map_err(|err| format!("failed to initialize cipher: {err}"))?;

    let mut buffer = plaintext.clone();
    buffer.resize(plaintext.len() + 16, 0u8);
    let ciphertext = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .map_err(|err| format!("encryption failed: {err}"))?;

    let mut output_bytes = Vec::with_capacity(iv.len() + ciphertext.len());
    output_bytes.extend_from_slice(&iv);
    output_bytes.extend_from_slice(ciphertext);

    fs::write(&output, &output_bytes)
        .map_err(|err| format!("failed to write output file {:?}: {err}", output))?;

    println!(
        "Encrypted {:?} -> {:?} ({} bytes -> {})",
        args.input,
        output,
        plaintext.len(),
        output_bytes.len()
    );
    println!("IV (first 16 bytes) is prepended to ciphertext in the output file.");

    Ok(())
}

fn derive_key_from_password(password: &str) -> [u8; 32] {
    let digest = Sha256::digest(password.as_bytes());
    digest.into()
}

fn generate_random_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    iv
}

fn derive_output_path(input: &PathBuf) -> Result<PathBuf, String> {
    let file_name = input
        .file_name()
        .ok_or_else(|| format!("input path {:?} has no file name", input))?;
    let mut enc_name: OsString = file_name.to_os_string();
    enc_name.push(".enc");
    let mut output = input.clone();
    output.set_file_name(enc_name);
    Ok(output)
}
