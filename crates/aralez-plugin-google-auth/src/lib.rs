use std::sync::Arc;
use std::time::SystemTime;

use axum::http::StatusCode;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::Session;
use rand::distr::Alphanumeric;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use urlencoding::encode as url_encode;

use aralez_spec::{AuthPluginEntry, AuthValidator, Claims};

// 既存モジュールからインポート (パスは環境に合わせて調整してください)
use aralez_util::{build_error_resp, get_query_param, AUTH_CONNECTOR};
use aralez_util::jwt::{check_jwt, JWT_TOKEN};

// --- 設定・構造体定義 ---

#[derive(Debug, Deserialize)]
pub struct GoogleAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String, // 例: "https://myproxy.example.com/auth/google/callback"
    pub cookie_name: Option<String>,
}

pub struct GoogleAuth {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    callback_path: String,
    cookie_name: String,
    scheme: &'static str,
}

// Google Token API からのレスポンス構造体
#[derive(Deserialize)]
struct TokenResp {
    id_token: String,

    // ステートレス運用のためサーバー側では保存せず、意図的に不使用とする
    #[serde(rename = "refresh_token")]
    #[allow(dead_code)]
    _refresh_token: Option<String>,
}

// ステートレスPKCE実現のために Google state パラメータに詰める一時JWTのClaims
#[derive(Debug, Serialize, Deserialize)]
struct StateClaims {
    target_url: String,
    code_verifier: String,
    exp: u64,
}

// --- AuthValidator トレイトの実装 ---

#[async_trait::async_trait]
impl AuthValidator for GoogleAuth {
    async fn validate(&self, session: &mut Session) -> Result<(), ResponseHeader> {
        // 1. CookieからセッションJWTを取得し検証 (認証済みアクセス)
        if let Some(token) = get_cookie(session, &self.cookie_name) {
            if let Some(jwt_secret) = JWT_TOKEN.clone() {
                if check_jwt(&token, jwt_secret.as_ref()) {
                    return Ok(());
                }
            }
        }

        let uri = session.req_header().uri.clone();
        let path = uri.path();

        // 2. Google認証後のコールバック処理
        if path == self.callback_path {
            let code = get_query_param(session, "code");
            let state_jwt = get_query_param(session, "state");

            if let (Some(code), Some(state_jwt)) = (code, state_jwt) {
                let jwt_secret = match JWT_TOKEN.clone() {
                    Some(s) => s,
                    None => return Err(build_error_resp(StatusCode::INTERNAL_SERVER_ERROR)),
                };

                // state (JWT) を復号して元の遷移先URLと code_verifier を取り出す
                if let Some((target_url, code_verifier)) = decode_state_token(&state_jwt, &jwt_secret) {
                    // Googleへトークン要求 (PKCE検証付き)
                    match self.exchange_code_for_token(&code, &code_verifier).await {
                        Ok(id_token) => {
                            // IDトークンからユーザー情報を抽出して独自セッションJWTを生成
                            let session_jwt = match create_session_jwt(&id_token) {
                                Ok(jwt) => jwt,
                                Err(_) => return Err(build_error_resp(StatusCode::INTERNAL_SERVER_ERROR)),
                            };

                            // Cookieをセットして元のURLへリダイレクト
                            let mut resp = ResponseHeader::build(StatusCode::FOUND, None).unwrap();
                            let secure_flag = if self.scheme == "https" { "; Secure" } else { "" };
                            let cookie_header = format!(
                                "{}={}; Path=/; HttpOnly{}; SameSite=Lax; Max-Age=86400",
                                self.cookie_name, session_jwt, secure_flag
                            );
                            resp.insert_header("Set-Cookie", cookie_header).ok();
                            resp.insert_header("Location", target_url).ok();
                            return Err(resp);
                        }
                        Err(e) => {
                            log::warn!("Google Auth token exchange failed: {:?}", e);
                            return Err(build_error_resp(StatusCode::INTERNAL_SERVER_ERROR));
                        }
                    }
                }
            }
            return Err(build_error_resp(StatusCode::BAD_REQUEST));
        }

        // 3. 未認証の場合: PKCEを準備してGoogle認可画面へリダイレクト
        let jwt_secret = match JWT_TOKEN.clone() {
            Some(s) => s,
            None => return Err(build_error_resp(StatusCode::INTERNAL_SERVER_ERROR)),
        };

        let host = session
            .get_header("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost");

        let current_url = format!("{}://{}{}", self.scheme, host, uri);

        // PKCE 用の Verifier と Challenge を生成
        let code_verifier = generate_code_verifier();
        let code_challenge = generate_code_challenge(&code_verifier);

        // state パラメータ（遷移先URL + code_verifier）をJWT化
        let state_jwt = match create_state_token(&current_url, &code_verifier, &jwt_secret) {
            Ok(jwt) => jwt,
            Err(_) => return Err(build_error_resp(StatusCode::INTERNAL_SERVER_ERROR)),
        };

        let auth_url = format!(
            "https://accounts.google.com/o/oauth2/v2/auth?\
            client_id={}&redirect_uri={}&response_type=code&\
            scope=openid%20email%20profile&\
            state={}&code_challenge={}&code_challenge_method=S256",
            self.client_id,
            url_encode(&self.redirect_uri),
            url_encode(&state_jwt),
            code_challenge
        );

        let mut resp = ResponseHeader::build(StatusCode::FOUND, None).unwrap();
        resp.insert_header("Location", auth_url).ok();
        Err(resp)
    }
}

// --- ヘルパー関数群 ---

impl GoogleAuth {
    // Google Token API と通信し、IDトークンを取得する (PKCE対応)
    async fn exchange_code_for_token(&self, code: &str, code_verifier: &str) -> Result<String, Box<dyn std::error::Error>> {
        let peer = HttpPeer::new(("oauth2.googleapis.com", 443), true, "oauth2.googleapis.com".to_string());
        let (mut http_session, _) = AUTH_CONNECTOR.get_http_session(&peer).await?;

        let body = format!(
            "code={}&client_id={}&client_secret={}&redirect_uri={}&grant_type=authorization_code&code_verifier={}",
            url_encode(code),
            url_encode(&self.client_id),
            url_encode(&self.client_secret),
            url_encode(&self.redirect_uri),
            url_encode(code_verifier)
        );

        let mut req = RequestHeader::build("POST", b"/token", None)?;
        req.insert_header("Host", "oauth2.googleapis.com")?;
        req.insert_header("Content-Type", "application/x-www-form-urlencoded")?;
        req.insert_header("Content-Length", body.len().to_string())?;

        http_session.write_request_header(Box::new(req)).await?;

        // Pingora の write_request_body (Bytes, end_flag) を使用
        http_session.write_request_body(Bytes::from(body), true).await?;

        http_session.read_response_header().await?;
        let mut resp_body = Vec::new();
        while let Some(chunk) = http_session.read_response_body().await? {
            resp_body.extend_from_slice(&chunk);
        }

        AUTH_CONNECTOR.release_http_session(http_session, &peer, None).await;

        let token_resp: TokenResp = serde_json::from_slice(&resp_body)?;

        // 【意図的な破棄】デストラクチャリングで取り出し、明示的に drop
        let TokenResp { id_token, _refresh_token } = token_resp;
        if _refresh_token.is_some() {
            log::debug!("Google refresh_token was received, but discarded for stateless architecture.");
        }
        drop(_refresh_token);

        Ok(id_token)
    }
}

// PKCE: 乱数から code_verifier を生成
fn generate_code_verifier() -> String {
    let bytes: Vec<u8> = rand::rng().sample_iter(&Alphanumeric).take(64).collect();
    URL_SAFE_NO_PAD.encode(bytes)
}

// PKCE: SHA256ハッシュから code_challenge を生成
fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash)
}

// State 用の短命 JWT を生成 (有効期限 10分)
fn create_state_token(target_url: &str, code_verifier: &str, secret: &str) -> Result<String, Box<dyn std::error::Error>> {
    let exp = SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() + 600;
    let claims = StateClaims {
        target_url: target_url.to_string(),
        code_verifier: code_verifier.to_string(),
        exp,
    };
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))?;
    Ok(token)
}

// State (JWT) を検証・復号
fn decode_state_token(state_jwt: &str, secret: &str) -> Option<(String, String)> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let validation = Validation::new(Algorithm::HS256);
    let data = decode::<StateClaims>(state_jwt, &key, &validation).ok()?;
    Some((data.claims.target_url, data.claims.code_verifier))
}

// Google の IDトークンから email を抜き出し、自前システム用の Claims / JWT を発行
fn create_session_jwt(id_token: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid ID token format".into());
    }
    let decoded = URL_SAFE_NO_PAD.decode(parts[1])?;
    let payload: serde_json::Value = serde_json::from_slice(&decoded)?;
    let email = payload.get("email").and_then(|v| v.as_str()).unwrap_or("unknown");

    let now = SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let claims = Claims {
        master_key: "google_auth".to_string(),
        owner: email.to_string(),
        exp: now + 86400, // 24時間有効
        random: None,
    };

    let jwt_secret = JWT_TOKEN.clone().ok_or("JWT_KEY environment variable not set")?;
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(jwt_secret.as_bytes()))?;
    Ok(token)
}

// Header から Cookie を取得するヘルパー
fn get_cookie(session: &Session, name: &str) -> Option<String> {
    let cookie_header = session.req_header().headers.get("cookie")?;
    let cookie_str = cookie_header.to_str().ok()?;
    for part in cookie_str.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

// --- プラグインの登録 ---

fn create_google_auth_validator(option: Option<noyalib::Value>) -> Result<Arc<dyn AuthValidator>, Box<dyn std::error::Error>> {
    let opt = option.ok_or("Missing Google auth configuration")?;
    let config: GoogleAuthConfig = noyalib::from_value(&opt)?;

    // redirect_uri からコールバックのパス（例: "/auth/google/callback"）を割り出す
    let callback_path = if let Some(idx) = config.redirect_uri.find("://") {
        let without_scheme = &config.redirect_uri[idx + 3..];
        if let Some(path_idx) = without_scheme.find('/') {
            without_scheme[path_idx..].to_string()
        } else {
            "/".to_string()
        }
    } else {
        config.redirect_uri.clone()
    };

    let scheme = if config.redirect_uri.starts_with("https://") { "https" } else { "http" };

    Ok(Arc::new(GoogleAuth {
        client_id: config.client_id,
        client_secret: config.client_secret,
        redirect_uri: config.redirect_uri,
        callback_path,
        cookie_name: config.cookie_name.unwrap_or_else(|| "aralez_session".to_string()),
        scheme: scheme,
    }))
}

inventory::submit! {
    AuthPluginEntry {
        name: "google",
        create: create_google_auth_validator,
    }
}
