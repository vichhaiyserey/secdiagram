use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;

mod handlers;
mod models;

pub fn create_app() -> Router {
    Router::new()
        .route("/health", get(handlers::health_check))
        .route("/users/search", get(handlers::search_users))
        .route("/users/profile", get(handlers::read_profile))
        .route("/users/export", post(handlers::export_data))
        .route("/fetch", get(handlers::fetch_remote))
}

#[tokio::main]
async fn main() {
    let app = create_app();
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
