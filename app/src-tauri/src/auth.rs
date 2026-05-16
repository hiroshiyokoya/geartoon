//! Nintendo Switch Online (NSO) OAuth 認証フローの Rust 実装。
//!
//! フロー全体:
//! ```text
//! 1. Nintendo Account ログインURLをブラウザで開く（PKCE付き OAuth2）
//! 2. npf71b963c1b7b6d119://auth#... へリダイレクト → deep-link でキャッチ
//! 3. session_token_code → session_token（長期保存）
//! 4. session_token → id_token（15分）
//! 5. id_token → f-token（POST https://api.imink.app/f）
//! 6. id_token + f-token → gtoken（Web Service Token / 約2時間）
//! 7. gtoken → bulletToken（約2時間）
//! ```
//!
//! 認証情報の永続化:
//! - `session_token` のみ長期保存が必要（tauri-plugin-store に保存）。
//!   将来的には OS キーチェーン（tauri-plugin-keyring）への移行が望ましいが、
//!   Windows ビルドの安定性を優先して現状は store を使用。
//! - `gtoken` / `bulletToken` は短命なため毎回再取得する。

use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use tauri::{AppHandle, State};
use tauri_plugin_store::StoreExt;

// ---------------------------------------------------------------------------
// 定数
// ---------------------------------------------------------------------------

/// Nintendo Switch Online アプリ (ZNCA) の client_id。
const CLIENT_ID: &str = "71b963c1b7b6d119";
/// OAuth2 リダイレクト先のカスタムスキーム URL（npf<client_id>://auth）。
const REDIRECT_URI: &str = "npf71b963c1b7b6d119://auth";
/// 認可リクエストの scope。
const SCOPE: &str = "openid user user.birthday user.screenName";

/// Nintendo Account 認可エンドポイント。
const NA_AUTHORIZE_URL: &str = "https://accounts.nintendo.com/connect/1.0.0/authorize";
/// session_token_code → session_token 交換エンドポイント。
const NA_SESSION_TOKEN_URL: &str = "https://accounts.nintendo.com/connect/1.0.0/api/session_token";
/// session_token → id_token / access_token 交換エンドポイント。
const NA_TOKEN_URL: &str = "https://accounts.nintendo.com/connect/1.0.0/api/token";
/// Nintendo Account ユーザー情報エンドポイント（birthday/country 取得用）。
const NA_USER_ME_URL: &str = "https://api.accounts.nintendo.com/2.0.0/users/me";

/// Coral (znc) API: Account/Login（gtoken 取得元の login）。
const CORAL_LOGIN_URL: &str = "https://api-lp1.znc.srv.nintendo.net/v4/Account/Login";
/// Coral (znc) API: Game/GetWebServiceToken（gtoken 取得）。
const CORAL_GET_WEB_SERVICE_TOKEN_URL: &str =
    "https://api-lp1.znc.srv.nintendo.net/v4/Game/GetWebServiceToken";

/// imink f-token 生成 API。
const IMINK_F_URL: &str = "https://api.imink.app/f";

/// SplatNet3 bullet_token エンドポイント。
const SPLATNET3_BULLET_TOKEN_URL: &str =
    "https://api.lp1.av5ja.srv.nintendo.net/api/bullet_tokens";
/// SplatNet3 (Splatoon3) の Web Service ID。
const SPLATNET3_WEB_SERVICE_ID: u64 = 4_834_290_508_791_808;

/// Coral アプリのバージョン（remote config の `coral.znca_version` に対応）。
/// 実運用では nxapi-remote-config.json から動的に読むのが望ましい。
const ZNCA_VERSION: &str = "3.3.0";
/// SplatNet3 WebView バージョン（remote config の `coral_gws_splatnet3.app_ver`）。
const SPLATNET3_WEB_VIEW_VER: &str = "10.0.0-dfefd0af";

/// imink hash_method: Coral の Account/Login 用。
const HASH_METHOD_CORAL: u8 = 1;
/// imink hash_method: Web Service Token 用。
const HASH_METHOD_WEB_SERVICE: u8 = 2;

/// store のファイル名と session_token のキー。
const STORE_FILE: &str = "auth.json";
const STORE_KEY_SESSION_TOKEN: &str = "session_token";

// ---------------------------------------------------------------------------
// アプリ状態（PKCE の code_verifier / state を保持）
// ---------------------------------------------------------------------------

/// `start_login` が生成し `handle_auth_redirect` が消費する PKCE パラメータ。
#[derive(Default)]
pub struct AuthState {
    inner: Mutex<Option<PendingAuth>>,
}

#[derive(Clone)]
struct PendingAuth {
    /// PKCE code_verifier（session_token_code_verifier として送信）。
    verifier: String,
    /// CSRF 対策の state（リダイレクトで照合）。
    state: String,
}

// ---------------------------------------------------------------------------
// PKCE / ユーティリティ
// ---------------------------------------------------------------------------

/// URL-safe Base64（パディングなし）でエンコードする。
fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// 指定バイト数のランダム値を URL-safe Base64 で返す。
fn random_b64url(len: usize) -> String {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    b64url(&buf)
}

/// PKCE: code_verifier から S256 challenge を導出する。
fn code_challenge_s256(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    b64url(&hasher.finalize())
}

/// 現在の Unix 時刻（秒）。
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// reqwest クライアントを構築する（共通設定）。
fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .build()
        .map_err(|e| format!("HTTP クライアント構築失敗: {e}"))
}

// ---------------------------------------------------------------------------
// レスポンス型
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SessionTokenResponse {
    session_token: String,
}

#[derive(Deserialize)]
struct NaTokenResponse {
    id_token: String,
    access_token: String,
}

#[derive(Deserialize)]
struct NaUserMe {
    id: String,
    birthday: String,
    country: String,
    language: String,
}

#[derive(Deserialize)]
struct IminkFResponse {
    f: String,
    request_id: String,
    timestamp: serde_json::Value,
}

/// Coral Account/Login のレスポンス（必要部分のみ）。
#[derive(Deserialize)]
struct CoralLoginResponse {
    result: Option<CoralLoginResult>,
}

#[derive(Deserialize)]
struct CoralLoginResult {
    #[serde(rename = "webApiServerCredential")]
    web_api_server_credential: CoralCredential,
    user: CoralUser,
}

#[derive(Deserialize)]
struct CoralCredential {
    #[serde(rename = "accessToken")]
    access_token: String,
}

#[derive(Deserialize)]
struct CoralUser {
    id: u64,
}

/// Coral GetWebServiceToken のレスポンス（必要部分のみ）。
#[derive(Deserialize)]
struct WebServiceTokenResponse {
    result: Option<WebServiceTokenResult>,
}

#[derive(Deserialize)]
struct WebServiceTokenResult {
    #[serde(rename = "accessToken")]
    access_token: String,
}

#[derive(Deserialize)]
struct BulletTokenResponse {
    #[serde(rename = "bulletToken")]
    bullet_token: String,
}

/// `get_bullet_token` がフロントに返す結果。
#[derive(Serialize)]
pub struct BulletTokenResult {
    pub bullet_token: String,
    pub gtoken: String,
    pub country: String,
    pub language: String,
}

// ---------------------------------------------------------------------------
// Tauri コマンド
// ---------------------------------------------------------------------------

/// ステップ 1: PKCE パラメータを生成し、Nintendo ログイン URL を構築して
/// ブラウザで開く。`code_verifier` / `state` はアプリ状態に保存する。
#[tauri::command]
pub fn start_login(app: AppHandle, state: State<'_, AuthState>) -> Result<String, String> {
    // PKCE: code_verifier（32バイト）と state（36バイト）を生成。
    let verifier = random_b64url(32);
    let csrf_state = random_b64url(36);
    let challenge = code_challenge_s256(&verifier);

    // 後続の handle_auth_redirect で照合・消費するため保存。
    {
        let mut guard = state.inner.lock().map_err(|e| e.to_string())?;
        *guard = Some(PendingAuth {
            verifier: verifier.clone(),
            state: csrf_state.clone(),
        });
    }

    // 認可 URL を組み立てる。
    let url = format!(
        "{base}?state={state}&redirect_uri={redirect}&client_id={client}\
         &scope={scope}&response_type=session_token_code\
         &session_token_code_challenge={challenge}\
         &session_token_code_challenge_method=S256&theme=login_form",
        base = NA_AUTHORIZE_URL,
        state = urlencode(&csrf_state),
        redirect = urlencode(REDIRECT_URI),
        client = CLIENT_ID,
        scope = urlencode(SCOPE),
        challenge = challenge,
    );

    // 既定ブラウザで開く（tauri-plugin-shell の opener を利用）。
    use tauri_plugin_shell::ShellExt;
    app.shell()
        .open(&url, None)
        .map_err(|e| format!("ブラウザ起動失敗: {e}"))?;

    Ok(url)
}

/// 最小限の URL エンコード（クエリ値用）。
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// ステップ 2-3: deep link URL から `session_token_code` を抽出し、
/// Nintendo API で `session_token` を取得して store に保存する。
#[tauri::command]
pub async fn handle_auth_redirect(
    app: AppHandle,
    state: State<'_, AuthState>,
    url: String,
) -> Result<(), String> {
    // npf...://auth#session_token_code=...&state=...&session_state=...
    // フラグメント部をパースする。
    let fragment = url
        .split_once('#')
        .map(|(_, f)| f.to_string())
        .ok_or_else(|| "リダイレクト URL にフラグメントがありません".to_string())?;

    let mut session_token_code: Option<String> = None;
    let mut returned_state: Option<String> = None;
    for pair in fragment.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "session_token_code" => session_token_code = Some(v.to_string()),
                "state" => returned_state = Some(v.to_string()),
                _ => {}
            }
        }
    }

    let code = session_token_code
        .ok_or_else(|| "session_token_code が見つかりません".to_string())?;

    // 保存しておいた PKCE パラメータを取り出し、state を照合する。
    let pending = {
        let mut guard = state.inner.lock().map_err(|e| e.to_string())?;
        guard.take().ok_or_else(|| {
            "進行中のログインがありません（start_login を先に呼んでください）".to_string()
        })?
    };
    if let Some(rs) = returned_state {
        if rs != pending.state {
            return Err("state が一致しません（CSRF の可能性）".to_string());
        }
    }

    // session_token_code → session_token（application/x-www-form-urlencoded）。
    let client = http_client()?;
    let params = [
        ("client_id", CLIENT_ID),
        ("session_token_code", code.as_str()),
        ("session_token_code_verifier", pending.verifier.as_str()),
    ];
    let resp = client
        .post(NA_SESSION_TOKEN_URL)
        .header("User-Agent", "NASDKAPI; Android")
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("session_token リクエスト失敗: {e}"))?;

    if !resp.status().is_success() {
        let s = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("session_token 取得失敗 ({s}): {body}"));
    }

    let parsed: SessionTokenResponse = resp
        .json()
        .await
        .map_err(|e| format!("session_token レスポンス解析失敗: {e}"))?;

    // session_token を store に保存（長期保存）。
    let store = app
        .store(STORE_FILE)
        .map_err(|e| format!("store オープン失敗: {e}"))?;
    store.set(
        STORE_KEY_SESSION_TOKEN,
        serde_json::Value::String(parsed.session_token),
    );
    store
        .save()
        .map_err(|e| format!("store 保存失敗: {e}"))?;

    Ok(())
}

/// ステップ 4-7: 保存済み `session_token` から
/// id_token → f-token → Coral login (gtoken 元) → WebServiceToken (gtoken)
/// → bulletToken を順に取得して返す。
#[tauri::command]
pub async fn get_bullet_token(app: AppHandle) -> Result<BulletTokenResult, String> {
    // 保存済み session_token を読む。
    let session_token = {
        let store = app
            .store(STORE_FILE)
            .map_err(|e| format!("store オープン失敗: {e}"))?;
        store
            .get(STORE_KEY_SESSION_TOKEN)
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .ok_or_else(|| "未ログインです（session_token がありません）".to_string())?
    };

    let client = http_client()?;

    // --- ステップ 4: session_token → id_token / access_token ---
    let token_body = serde_json::json!({
        "client_id": CLIENT_ID,
        "session_token": session_token,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer-session-token",
    });
    let na_token: NaTokenResponse = client
        .post(NA_TOKEN_URL)
        .header("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 8.0.0)")
        .header("Accept", "application/json")
        .json(&token_body)
        .send()
        .await
        .map_err(|e| format!("id_token リクエスト失敗: {e}"))?
        .json()
        .await
        .map_err(|e| format!("id_token レスポンス解析失敗: {e}"))?;

    // Nintendo Account ユーザー情報（birthday/country/language が Coral login で必要）。
    let user: NaUserMe = client
        .get(NA_USER_ME_URL)
        .header("User-Agent", "NASDKAPI; Android")
        .header("Accept", "application/json")
        .header("Authorization", format!("Bearer {}", na_token.access_token))
        .send()
        .await
        .map_err(|e| format!("users/me リクエスト失敗: {e}"))?
        .json()
        .await
        .map_err(|e| format!("users/me レスポンス解析失敗: {e}"))?;

    // --- ステップ 5: id_token → f-token (Coral login 用, hash_method=1) ---
    let f_coral = request_f(
        &client,
        &na_token.id_token,
        HASH_METHOD_CORAL,
        Some(&user.id),
        None,
    )
    .await?;

    // --- ステップ 6a: Coral Account/Login（gtoken 取得の前段） ---
    let login_body = serde_json::json!({
        "parameter": {
            "naIdToken": na_token.id_token,
            "naBirthday": user.birthday,
            "naCountry": user.country,
            "language": user.language,
            "timestamp": f_coral.timestamp,
            "requestId": f_coral.request_id,
            "f": f_coral.f,
        }
    });
    let login: CoralLoginResponse = client
        .post(CORAL_LOGIN_URL)
        .header("X-Platform", "Android")
        .header("X-ProductVersion", ZNCA_VERSION)
        .header(
            "User-Agent",
            format!("com.nintendo.znca/{ZNCA_VERSION}(Android/12)"),
        )
        .header("Content-Type", "application/json; charset=utf-8")
        .header("Accept", "application/json")
        .json(&login_body)
        .send()
        .await
        .map_err(|e| format!("Coral login リクエスト失敗: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Coral login レスポンス解析失敗: {e}"))?;

    let login_result = login
        .result
        .ok_or_else(|| "Coral login レスポンスに result がありません".to_string())?;
    let coral_access_token = login_result.web_api_server_credential.access_token;
    let coral_user_id = login_result.user.id;

    // --- ステップ 6b: id_token → f-token (WebServiceToken 用, hash_method=2) ---
    // ここでの token は Coral の accessToken。coral_user_id を付与する。
    let f_web = request_f(
        &client,
        &coral_access_token,
        HASH_METHOD_WEB_SERVICE,
        Some(&user.id),
        Some(coral_user_id),
    )
    .await?;

    // --- ステップ 6c: GetWebServiceToken → gtoken ---
    let gws_body = serde_json::json!({
        "parameter": {
            "id": SPLATNET3_WEB_SERVICE_ID,
            "registrationToken": coral_access_token,
            "f": f_web.f,
            "requestId": f_web.request_id,
            "timestamp": f_web.timestamp,
        }
    });
    let gws: WebServiceTokenResponse = client
        .post(CORAL_GET_WEB_SERVICE_TOKEN_URL)
        .header("X-Platform", "Android")
        .header("X-ProductVersion", ZNCA_VERSION)
        .header(
            "User-Agent",
            format!("com.nintendo.znca/{ZNCA_VERSION}(Android/12)"),
        )
        .header("Content-Type", "application/json; charset=utf-8")
        .header("Accept", "application/json")
        .header("Authorization", format!("Bearer {coral_access_token}"))
        .json(&gws_body)
        .send()
        .await
        .map_err(|e| format!("GetWebServiceToken リクエスト失敗: {e}"))?
        .json()
        .await
        .map_err(|e| format!("GetWebServiceToken レスポンス解析失敗: {e}"))?;

    let gtoken = gws
        .result
        .ok_or_else(|| "GetWebServiceToken に result がありません".to_string())?
        .access_token;

    // --- ステップ 7: gtoken → bulletToken ---
    let bullet: BulletTokenResponse = client
        .post(SPLATNET3_BULLET_TOKEN_URL)
        .header("Content-Type", "application/json")
        .header("Accept", "*/*")
        .header("X-Requested-With", "XMLHttpRequest")
        .header("X-Web-View-Ver", SPLATNET3_WEB_VIEW_VER)
        .header("X-NACOUNTRY", &user.country)
        .header("Accept-Language", &user.language)
        .header("X-GameWebToken", &gtoken)
        .header(
            "User-Agent",
            "Mozilla/5.0 (Linux; Android 8.0.0) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/94.0.4606.61 Mobile Safari/537.36",
        )
        .header("Referer", "https://api.lp1.av5ja.srv.nintendo.net/")
        .body("")
        .send()
        .await
        .map_err(|e| format!("bullet_token リクエスト失敗: {e}"))?
        .json()
        .await
        .map_err(|e| format!("bullet_token レスポンス解析失敗: {e}"))?;

    Ok(BulletTokenResult {
        bullet_token: bullet.bullet_token,
        gtoken,
        country: user.country,
        language: user.language,
    })
}

/// imink f-token API を呼び出す。
/// - `token`: hash_method=1 では NA の id_token、=2 では Coral の accessToken。
/// - `na_id`: Nintendo Account ID。
/// - `coral_user_id`: hash_method=2 のときに付与する Coral ユーザー ID。
async fn request_f(
    client: &reqwest::Client,
    token: &str,
    hash_method: u8,
    na_id: Option<&str>,
    coral_user_id: Option<u64>,
) -> Result<IminkFResponse, String> {
    let mut body = serde_json::json!({
        "token": token,
        "hash_method": hash_method,
    });
    if let Some(id) = na_id {
        body["na_id"] = serde_json::Value::String(id.to_string());
    }
    if let Some(cid) = coral_user_id {
        body["coral_user_id"] = serde_json::Value::String(cid.to_string());
    }

    let resp = client
        .post(IMINK_F_URL)
        .header("Content-Type", "application/json")
        .header("User-Agent", "geartoon/0.1.0")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("imink f リクエスト失敗: {e}"))?;

    if !resp.status().is_success() {
        let s = resp.status();
        let b = resp.text().await.unwrap_or_default();
        return Err(format!("imink f 失敗 ({s}): {b}"));
    }

    resp.json::<IminkFResponse>()
        .await
        .map_err(|e| format!("imink f レスポンス解析失敗: {e}"))
}

/// session_token が保存済みか（= ログイン済みか）を返す。
#[tauri::command]
pub fn check_auth_status(app: AppHandle) -> Result<bool, String> {
    let store = app
        .store(STORE_FILE)
        .map_err(|e| format!("store オープン失敗: {e}"))?;
    Ok(store
        .get(STORE_KEY_SESSION_TOKEN)
        .and_then(|v| v.as_str().map(|s| !s.is_empty()))
        .unwrap_or(false))
}

/// 保存済みトークンを削除してログアウトする。
#[tauri::command]
pub fn logout(app: AppHandle) -> Result<(), String> {
    let store = app
        .store(STORE_FILE)
        .map_err(|e| format!("store オープン失敗: {e}"))?;
    store.delete(STORE_KEY_SESSION_TOKEN);
    store
        .save()
        .map_err(|e| format!("store 保存失敗: {e}"))?;
    Ok(())
}

/// `now_unix` は将来のトークン有効期限管理用。現状は未使用警告抑制のため公開。
#[allow(dead_code)]
pub fn _touch_unused() -> u64 {
    now_unix()
}
