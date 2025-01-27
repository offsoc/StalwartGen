use ring::rand::SystemRandom; // 引入ring库中的随机数生成器
use ring::signature::{Ed25519KeyPair, KeyPair}; // 引入ring库中的签名模块
use base64::{engine::general_purpose::STANDARD, Engine}; // 引入base64库用于编码和解码
use std::fs::File; // 引入标准库中的文件模块
use std::io::Write; // 引入标准库中的写入模块
use std::env; // 引入标准库中的环境变量模块
use rand::{Rng}; // 引入rand库中的随机数生成器
use chrono::{DateTime, Utc}; // 引入chrono库用于时间处理
use rand::distr::Alphanumeric; // 引入rand库中的随机数生成器

const VERSION: &str = "v1.3.0"; // 版本号
const AUTHOR: &str = "Stalwart Labs Ltd <hello@stalw.art>"; // 作者信息

// 定义print_help函数，用于打印帮助信息
fn print_help() {
    println!("Author: {}", AUTHOR);
    println!("Version: {}", VERSION);
    
    println!("Usage: StalwartGen [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --help                Show this help message and exit");
    println!("  --no-keys             Do not generate new keys");
    println!("  --domain <domain>     Domain for the license (default: example.com)");
    println!("  --accounts <number>   Number of accounts (default: 100)");
    println!("  --valid-from <time>   License valid from timestamp (default: current time)");
    println!("  --valid-to <time>     License valid to timestamp (default: 5 years from valid-from)");
    println!();
}

// 定义main函数，程序入口
fn main() {
    let args: Vec<String> = env::args().collect(); // 获取命令行参数
    
    // 检查是否包含 --help 参数
    if args.contains(&"--help".to_string()) {
        print_help();
        return;
    }

    // 解析命令行参数
    let mut generate_keys = true;
    let mut domain = "apt27.us.kg".to_string();
    let mut accounts = 100000;
    let mut valid_from = Utc::now().timestamp() as u64;
    let mut valid_to = valid_from + 5 * 365 * 24 * 60 * 60;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--no-keys" => generate_keys = false,
            "--domain" => {
                if i + 1 < args.len() {
                    domain = args[i + 1].clone();
                    i += 1;
                } else {
                    eprintln!("Error: --domain option requires a value");
                    return;
                }
            }
            "--accounts" => {
                if i + 1 < args.len() {
                    accounts = args[i + 1].parse().unwrap_or(100);
                    i += 1;
                } else {
                    eprintln!("Error: --accounts option requires a value");
                    return;
                }
            }
            "--valid-from" => {
                if i + 1 < args.len() {
                    valid_from = args[i + 1].parse().unwrap_or(Utc::now().timestamp() as u64);
                    i += 1;
                } else {
                    eprintln!("Error: --valid-from option requires a value");
                    return;
                }
            }
            "--valid-to" => {
                if i + 1 < args.len() {
                    valid_to = args[i + 1].parse().unwrap_or(valid_from + 5 * 365 * 24 * 60 * 60);
                    i += 1;
                } else {
                    eprintln!("Error: --valid-to option requires a value");
                    return;
                }
            }
            _ => {
                eprintln!("Error: Unknown option {}", args[i]);
                return;
            }
        }
        i += 1;
    }

    // 生成密钥对
    let (key_pair, _pkcs8_bytes) = if generate_keys {
        let (key_pair, pkcs8_bytes) = create_key_pair().expect("Failed to create key pair");

        // 保存私钥
        let mut file = File::create("private_key.pkcs8").expect("Failed to create private key file");
        file.write_all(&pkcs8_bytes).expect("Failed to write private key");

        // 保存公钥
        let public_key = key_pair.public_key().as_ref().to_vec();
        let mut file = File::create("public_key.txt").expect("Failed to create public key file");
        file.write_all(&public_key).expect("Failed to write public key");

        // 输出替换的公钥
        println!("Replace the public key in your code with the following:");
        println!("{:?}", public_key);

        (key_pair, pkcs8_bytes)
    } else {
        let pkcs8_bytes = std::fs::read("private_key.pkcs8").expect("Failed to read private key file");
        let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes).expect("Failed to create key pair from private key");
        (key_pair, pkcs8_bytes)
    };

    // 生成许可证密钥
    let license_key = generate_license_key(
        valid_from,
        valid_to,
        &domain,
        accounts,
        &key_pair,
    )
    .expect("Failed to generate license key");

    // 保存许可证密钥
    let mut file = File::create("license_key.txt").expect("Failed to create license key file");
    file.write_all(license_key.as_bytes())
        .expect("Failed to write license key");

    // 生成随机API密钥
    let api_key: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let mut file = File::create("api_key.txt").expect("Failed to create API key file");
    file.write_all(api_key.as_bytes())
        .expect("Failed to write API key");

    // 格式化有效期时间
    let valid_from_dt = DateTime::<Utc>::from_timestamp(valid_from as i64, 0).unwrap();
    let valid_to_dt = DateTime::<Utc>::from_timestamp(valid_to as i64, 0).unwrap();

    // 输出许可证信息
    println!("License Key\n{}", license_key);
    println!("API Key (for auto-renewal)\n{}", api_key);
    println!("Issued To\n{}", domain);
    println!("Licenses\n{}", accounts);
    println!("Validity\n{} to {}", valid_from_dt.format("%B %d, %Y"), valid_to_dt.format("%B %d, %Y"));
}

// 生成许可证密钥
fn generate_license_key(
    valid_from: u64,
    valid_to: u64,
    domain: &str,
    accounts: u32,
    private_key: &Ed25519KeyPair,
) -> Result<String, String> {
    let mut key_data = Vec::new();
    key_data.extend_from_slice(&valid_from.to_le_bytes());
    key_data.extend_from_slice(&valid_to.to_le_bytes());
    key_data.extend_from_slice(&accounts.to_le_bytes());
    key_data.extend_from_slice(&(domain.len() as u32).to_le_bytes());
    key_data.extend_from_slice(domain.as_bytes());

    let signature = private_key.sign(&key_data);
    key_data.extend_from_slice(signature.as_ref());

    Ok(STANDARD.encode(&key_data))
}

// 创建密钥对
fn create_key_pair() -> Result<(Ed25519KeyPair, Vec<u8>), ring::error::Unspecified> {
    let rng = SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
    Ok((key_pair, pkcs8_bytes.as_ref().to_vec()))
}
