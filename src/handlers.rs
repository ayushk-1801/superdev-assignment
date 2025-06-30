use axum::{extract::Json, response::IntoResponse};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use solana_program::{
    instruction::AccountMeta,
    pubkey::Pubkey as SolanaPubkey,
    system_program,
};

use crate::errors::AppError;
use crate::models::*;
use crate::utils::spl_token;

pub async fn generate_keypair() -> impl IntoResponse {
    let mut csprng = OsRng;
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let pubkey = bs58::encode(keypair.public.as_bytes()).into_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    ApiResponse::success(KeypairResponse { pubkey, secret })
}

pub async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<Json<ApiResponse<InstructionResponse>>, AppError> {
    let mint_authority_pubkey = SolanaPubkey::new_from_array(
        bs58::decode(&payload.mint_authority)
            .into_vec()
            .map_err(|_| AppError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| AppError::InvalidPublicKey)?,
    );

    let mint_pubkey = SolanaPubkey::new_from_array(
        bs58::decode(&payload.mint)
            .into_vec()
            .map_err(|_| AppError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| AppError::InvalidPublicKey)?,
    );

    let mut instruction_data = vec![0];
    instruction_data.push(payload.decimals);
    instruction_data.extend_from_slice(mint_authority_pubkey.as_ref());
    instruction_data.push(0);

    let accounts = vec![
        AccountMeta::new(mint_pubkey, false),
        AccountMeta::new_readonly(solana_program::sysvar::rent::id(), false),
    ];

    let response = InstructionResponse {
        program_id: spl_token::id().to_string(),
        accounts: accounts.into_iter().map(Into::into).collect(),
        instruction_data: general_purpose::STANDARD.encode(&instruction_data),
    };

    Ok(ApiResponse::success(response))
}

pub async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> Result<Json<ApiResponse<InstructionResponse>>, AppError> {
    let mint_pubkey = SolanaPubkey::new_from_array(
        bs58::decode(&payload.mint)
            .into_vec()
            .map_err(|_| AppError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| AppError::InvalidPublicKey)?,
    );

    let destination_pubkey = SolanaPubkey::new_from_array(
        bs58::decode(&payload.destination)
            .into_vec()
            .map_err(|_| AppError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| AppError::InvalidPublicKey)?,
    );

    let authority_pubkey = SolanaPubkey::new_from_array(
        bs58::decode(&payload.authority)
            .into_vec()
            .map_err(|_| AppError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| AppError::InvalidPublicKey)?,
    );

    let mut instruction_data = vec![7];
    instruction_data.extend_from_slice(&payload.amount.to_le_bytes());

    let accounts = vec![
        AccountMeta::new(mint_pubkey, false),
        AccountMeta::new(destination_pubkey, false),
        AccountMeta::new_readonly(authority_pubkey, true),
    ];

    let response = InstructionResponse {
        program_id: spl_token::id().to_string(),
        accounts: accounts.into_iter().map(Into::into).collect(),
        instruction_data: general_purpose::STANDARD.encode(&instruction_data),
    };

    Ok(ApiResponse::success(response))
}

pub async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> Result<Json<ApiResponse<SignMessageResponse>>, AppError> {
    let keypair_bytes_vec = bs58::decode(&payload.secret)
        .into_vec()
        .map_err(|_| AppError::InvalidSecretKey)?;

    let keypair_bytes: [u8; 64] = keypair_bytes_vec
        .try_into()
        .map_err(|_| AppError::InvalidSecretKey)?;

    let keypair = Keypair::from_bytes(&keypair_bytes).map_err(|_| AppError::InvalidSecretKey)?;

    let signature = keypair.sign(payload.message.as_bytes());

    let response = SignMessageResponse {
        signature: general_purpose::STANDARD.encode(signature.to_bytes()),
        public_key: bs58::encode(keypair.public.as_bytes()).into_string(),
        message: payload.message,
    };

    Ok(ApiResponse::success(response))
}

pub async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Result<Json<ApiResponse<VerifyMessageResponse>>, AppError> {
    let pubkey_bytes =
        bs58::decode(&payload.pubkey)
            .into_vec()
            .map_err(|_| AppError::InvalidPublicKey)?;
    let public_key =
        PublicKey::from_bytes(&pubkey_bytes).map_err(|_| AppError::InvalidPublicKey)?;

    let signature_bytes = general_purpose::STANDARD
        .decode(&payload.signature)
        .map_err(|_| AppError::InvalidSignature)?;
    let signature =
        Signature::from_bytes(&signature_bytes).map_err(|_| AppError::InvalidSignature)?;

    let valid = public_key
        .verify(payload.message.as_bytes(), &signature)
        .is_ok();

    let response = VerifyMessageResponse {
        valid,
        message: payload.message,
        pubkey: payload.pubkey,
    };

    Ok(ApiResponse::success(response))
}

pub async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> Result<Json<ApiResponse<InstructionResponse>>, AppError> {
    let from_pubkey = SolanaPubkey::new_from_array(
        bs58::decode(&payload.from)
            .into_vec()
            .map_err(|_| AppError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| AppError::InvalidPublicKey)?,
    );

    let to_pubkey = SolanaPubkey::new_from_array(
        bs58::decode(&payload.to)
            .into_vec()
            .map_err(|_| AppError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| AppError::InvalidPublicKey)?,
    );

    let instruction =
        solana_program::system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);

    let response = InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction.accounts.into_iter().map(Into::into).collect(),
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    };

    Ok(ApiResponse::success(response))
}

pub async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> Result<Json<ApiResponse<InstructionResponse>>, AppError> {
    let source_pubkey = SolanaPubkey::new_from_array(
        bs58::decode(&payload.source)
            .into_vec()
            .map_err(|_| AppError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| AppError::InvalidPublicKey)?,
    );
    let destination_pubkey = SolanaPubkey::new_from_array(
        bs58::decode(&payload.destination)
            .into_vec()
            .map_err(|_| AppError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| AppError::InvalidPublicKey)?,
    );
    let owner_pubkey = SolanaPubkey::new_from_array(
        bs58::decode(&payload.owner)
            .into_vec()
            .map_err(|_| AppError::InvalidPublicKey)?
            .try_into()
            .map_err(|_| AppError::InvalidPublicKey)?,
    );

    let mut instruction_data = vec![3];
    instruction_data.extend_from_slice(&payload.amount.to_le_bytes());

    let accounts = vec![
        AccountMeta::new(source_pubkey, false),
        AccountMeta::new(destination_pubkey, false),
        AccountMeta::new_readonly(owner_pubkey, true),
    ];

    let response = InstructionResponse {
        program_id: spl_token::id().to_string(),
        accounts: accounts.into_iter().map(Into::into).collect(),
        instruction_data: general_purpose::STANDARD.encode(&instruction_data),
    };
    Ok(ApiResponse::success(response))
} 