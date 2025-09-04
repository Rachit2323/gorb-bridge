
use candid::{CandidType, Principal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::indexer::TransferEvent;
use crate::indexer::IndexerState;
use crate::indexer::SignatureInfo;
mod indexer;

#[derive(CandidType, Serialize, Deserialize, Debug, Copy, Clone)]
pub enum SchnorrAlgorithm {
    #[serde(rename = "ed25519")]
    Ed25519,
}

type CanisterId = Principal;

#[derive(CandidType, Debug)]
struct ManagementCanisterSchnorrPublicKeyRequest {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: SchnorrKeyId,
}

#[derive(Serialize, Deserialize, CandidType, Debug)]
struct ManagementCanisterSchnorrPublicKeyReply {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug, Clone)]
struct SchnorrKeyId {
    pub algorithm: SchnorrAlgorithm,
    pub name: String,
}

#[derive(CandidType, Serialize, Debug)]
struct ManagementCanisterSignatureRequest {
    pub message: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: SchnorrKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct ManagementCanisterSignatureReply {
    pub signature: Vec<u8>,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
struct TransactionParams {
    pub base64_message: String,
    pub sender_public_key: String,
    pub blockhash: String,
    pub last_valid_block_height: u64,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
struct TransactionResult {
    pub success: bool,
    pub transaction_id: Option<String>,
    pub error: Option<String>,
}

async fn complete_transaction_rust(signature_hex: String) -> TransactionResult {
    ic_cdk::println!("Starting transaction completion with signature: {}...", &signature_hex[0..20.min(signature_hex.len())]);
    
    // Convert signature from hex to bytes
    let signature_bytes = match hex::decode(&signature_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            let error_msg = format!("Failed to decode signature hex: {}", e);
            ic_cdk::println!("ERROR: {}", error_msg);
            return TransactionResult {
                success: false,
                transaction_id: None,
                error: Some(error_msg),
            };
        }
    };
    
    ic_cdk::println!("Signature ({} bytes): {}...", signature_bytes.len(), &signature_hex[0..20.min(signature_hex.len())]);
    
    // Note: In a real implementation, you would need to:
    // 1. Get the base64_message, blockhash, and last_valid_block_height from somewhere
    // 2. Check if blockhash is still valid
    // 3. Create the wire transaction format
    // 4. Send the transaction to Solana network
    // 5. Monitor transaction status
    
    // For now, this is a placeholder that simulates the transaction process
    ic_cdk::println!("Transaction completion simulation - signature processed successfully");
    
    // Simulate transaction ID (in real implementation, this would come from Solana network)
    let simulated_tx_id = format!("{}...{}", &signature_hex[0..8], &signature_hex[signature_hex.len()-8..]);
    
    ic_cdk::println!("Simulated transaction ID: {}", simulated_tx_id);
    ic_cdk::println!("View on Solana Explorer: https://explorer.solana.com/tx/{}?cluster=devnet", simulated_tx_id);
    
    TransactionResult {
        success: true,
        transaction_id: Some(simulated_tx_id),
        error: None,
    }
}


#[ic_cdk::update]
async fn generate_keypair_solana_user() -> Result<String, String> {

    let request = ManagementCanisterSchnorrPublicKeyRequest {
        canister_id: None,
        derivation_path: vec![ic_cdk::api::caller().as_slice().to_vec()],
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: String::from("dfx_test_key"),
        },
    };

    ic_cdk::println!("generate_keypair_solana: {:?}" ,request);

    let (res,): (ManagementCanisterSchnorrPublicKeyReply,) = ic_cdk::call(
        Principal::management_canister(),
        "schnorr_public_key",
        (request,),
    )
    .await // Add the await keyword
    .map_err(|e| format!("schnorr_public_key failed {}", e.1))?;

    // Generate or obtain the private key

    ic_cdk::println!("res {:?}", res);
    let public_key_bytes = res.public_key.to_vec();


    // ic_cdk::println!("public_key_bytes {:?}", public_key_bytes);
    let hex_string: String = public_key_bytes.iter()
    .map(|b| format!("{:02X}", b)) // Convert each byte to uppercase hex
    .collect();

    ic_cdk::println!("Raw Public Key (Hex): {}", hex_string);


    if public_key_bytes.len() != 32 {
        return Err("Invalid public key length; expected 32 bytes".to_string());
    }

    // Convert the public key to a Solana address (Base58 encoding)
    // let solana_address = encode_base58(&public_key_bytes);
    let solana_address = bs58::encode(public_key_bytes).into_string();
    // let pubkey = Pubkey::new(&public_key_bytes);
    ic_cdk::println!("Solana Address: {}", solana_address);

    Ok(solana_address)
}



#[ic_cdk::update]
async fn generate_keypair_solana() -> Result<String, String> {

    let derivation_path = vec![vec![34, 93, 83, 88, 49, 84, 44, 44]];

    let request = ManagementCanisterSchnorrPublicKeyRequest {
        canister_id: None,
        derivation_path,
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: String::from("dfx_test_key"),
        },
    };

    ic_cdk::println!("generate_keypair_solana: {:?}" ,request);

    let (res,): (ManagementCanisterSchnorrPublicKeyReply,) = ic_cdk::call(
        Principal::management_canister(),
        "schnorr_public_key",
        (request,),
    )
    .await // Add the await keyword
    .map_err(|e| format!("schnorr_public_key failed {}", e.1))?;

    // Generate or obtain the private key

    ic_cdk::println!("res {:?}", res);
    let public_key_bytes = res.public_key.to_vec();


    // ic_cdk::println!("public_key_bytes {:?}", public_key_bytes);
    let hex_string: String = public_key_bytes.iter()
    .map(|b| format!("{:02X}", b)) // Convert each byte to uppercase hex
    .collect();

    ic_cdk::println!("Raw Public Key (Hex): {}", hex_string);


    if public_key_bytes.len() != 32 {
        return Err("Invalid public key length; expected 32 bytes".to_string());
    }

    // Convert the public key to a Solana address (Base58 encoding)
    // let solana_address = encode_base58(&public_key_bytes);
    let solana_address = bs58::encode(public_key_bytes).into_string();
    // let pubkey = Pubkey::new(&public_key_bytes);
    ic_cdk::println!("Solana Address: {}", solana_address);

    Ok(solana_address)
}



#[ic_cdk::update]
async fn sign_transaction_solana(hash: String) -> Result<String, String> {

    ic_cdk::println!("hash {:?}",hash);
    let hash_bytes = base64::decode(&hash)
    .map_err(|e| format!("Invalid Base64 string: {}", e))?;

    ic_cdk::println!("hash_bytes {:?}",hash_bytes);
    // Create a Sha256 hasher

    let derivation_path = vec![vec![34, 93, 83, 88, 49, 84, 44, 44]];


    let internal_request = ManagementCanisterSignatureRequest {
        message: hash_bytes,
        derivation_path,
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: String::from("dfx_test_key"),
        },
    };

    let (internal_reply,): (ManagementCanisterSignatureReply,) =
        ic_cdk::api::call::call_with_payment(
            Principal::management_canister(),
            "sign_with_schnorr",
            (internal_request,),
            26_153_846_153,
        )
        .await
        .map_err(|e| format!("sign_with_schnorr failed {e:?}"))?;

    // let transformed_signature = transform_signature_for_solana(&internal_reply.signature)
    // .map_err(|e| format!("Failed to transform signature: {}", e))?;

    ic_cdk::println!("internal_reply {:?}",internal_reply);
    
    // Convert the completeTransaction functionality to Rust
    complete_transaction_rust(hex::encode(&internal_reply.signature)).await;
    
    Ok(hex::encode(&internal_reply.signature))
}


ic_cdk::export_candid!();
