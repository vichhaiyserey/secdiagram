use axum::{
    extract::Query,
    response::IntoResponse,
    Json,
};
use std::process::Command;
use std::fs;

#[derive(serde::Deserialize)]
pub struct SearchParams {
    pub q: String,
}

#[derive(serde::Deserialize)]
pub struct ExportRequest {
    pub target: String,
}

pub async fn health_check() -> impl IntoResponse {
    "OK"
}

// VULNERABLE: SQL query built with dynamic format!
pub async fn search_users(Query(params): Query<SearchParams>) -> impl IntoResponse {
    let sql = format!("SELECT * FROM users WHERE name = '{}'", params.q);
    let _ = sqlx::query(&sql);
    "done"
}

// VULNERABLE: Command execution with tainted input and an unsafe memory block
pub async fn export_data(Json(payload): Json<ExportRequest>) -> impl IntoResponse {
    let cmd = format!("tar -czf /tmp/backup.tar.gz {}", payload.target);
    let _ = Command::new("sh").arg("-c").arg(&cmd).output();

    unsafe {
        let ptr: *const u8 = std::ptr::null();
        let _ = ptr.is_null();
    }

    "exported"
}

// VULNERABLE: Path traversal via fs::read_to_string
pub async fn read_profile(Query(params): Query<SearchParams>) -> impl IntoResponse {
    let path = format!("/var/data/profiles/{}", params.q);
    let content = fs::read_to_string(&path).unwrap_or_default();
    content
}

// VULNERABLE: SSRF via reqwest
pub async fn fetch_remote(Query(params): Query<SearchParams>) -> impl IntoResponse {
    let url = format!("https://api.external.com/{}", params.q);
    let resp = reqwest::get(&url).await;
    match resp {
        Ok(r) => r.text().await.unwrap_or_default(),
        Err(_) => "error".to_string(),
    }
}
