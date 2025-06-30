use axum::{http::StatusCode, response::{IntoResponse, Response}};
use crate::models::error_response;

#[derive(Debug)]
pub enum AppError {
    MissingFields,
    InvalidPublicKey,
    InvalidSecretKey,
    InvalidSignature,
    SigningError,
    VerificationFailed,
    InvalidAmount,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::MissingFields => (StatusCode::BAD_REQUEST, "Missing required fields"),
            AppError::InvalidPublicKey => (StatusCode::BAD_REQUEST, "Invalid public key provided"),
            AppError::InvalidSecretKey => (StatusCode::BAD_REQUEST, "Invalid secret key provided"),
            AppError::InvalidSignature => (StatusCode::BAD_REQUEST, "Invalid signature provided"),
            AppError::SigningError => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to sign message"),
            AppError::VerificationFailed => (StatusCode::OK, "Signature verification failed"),
            AppError::InvalidAmount => (StatusCode::BAD_REQUEST, "Invalid amount provided"),
        };
        error_response(status, message)
    }
} 