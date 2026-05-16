//! NSO 認証フローを CLI から対話的に試すツール。
//!
//! 実行:
//! ```text
//! cargo run --example auth_cli
//! ```
//!
//! フロー:
//! 1. PKCE パラメータを生成し、ログイン URL を表示。
//! 2. ブラウザでログイン後のリダイレクト URL を貼り付けてもらう。
//! 3. parse_auth_fragment → exchange_session_token_code で session_token 取得。
//! 4. fetch_bullet_token で bulletToken まで取得。
//! 5. 結果を表示。

use std::io::{self, Write};

use app_lib::auth::{
    build_login_url, exchange_session_token_code, fetch_bullet_token, generate_pkce,
    parse_auth_fragment,
};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("\nエラー: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    // 1. PKCE パラメータ生成 → ログイン URL を表示。
    let (verifier, state) = generate_pkce();
    let login_url = build_login_url(&verifier, &state);

    println!("=== NSO 認証フロー CLI ===\n");
    println!("以下の URL をブラウザで開いてログインしてください:\n");
    println!("{login_url}\n");

    // 2-3. リダイレクト URL を stdin から読み込む。
    print!("ログイン後にリダイレクトされた URL を貼り付けてください: ");
    io::stdout().flush().map_err(|e| e.to_string())?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("入力読み込み失敗: {e}"))?;
    let redirect_url = input.trim();

    // 4. parse_auth_fragment → state 照合 → exchange_session_token_code。
    let (code, returned_state) = parse_auth_fragment(redirect_url)?;
    if let Some(rs) = &returned_state {
        if rs != &state {
            return Err("state が一致しません（CSRF の可能性）".to_string());
        }
    }
    println!("\nsession_token_code を抽出しました。session_token を取得中...");

    let client = reqwest::Client::builder()
        .build()
        .map_err(|e| format!("HTTP クライアント構築失敗: {e}"))?;

    let session_token = exchange_session_token_code(&code, &verifier, &client).await?;
    println!(
        "session_token を取得しました（先頭20文字: {}）",
        &session_token.chars().take(20).collect::<String>()
    );

    // 5. fetch_bullet_token で bulletToken まで取得。
    println!("\nbulletToken を取得中...（数秒かかります）");
    let result = fetch_bullet_token(&session_token, &client).await?;

    // 6. 結果を表示。
    println!("\n=== 取得成功 ===");
    println!(
        "bulletToken (先頭20文字): {}",
        &result.bullet_token.chars().take(20).collect::<String>()
    );
    println!("country: {}", result.country);
    println!("language: {}", result.language);

    Ok(())
}
