use candid::CandidType;
use ic_cdk::update;
use serde::{Deserialize, Serialize};
use ic_cdk::api::management_canister::http_request::CanisterHttpRequestArgument;
use ic_cdk::api::management_canister::http_request::{self, HttpHeader, HttpMethod};
use serde_json::{json, Value};
use ic_cdk::api::management_canister::http_request::http_request;
use std::cell::RefCell;
use ic_cdk_timers::TimerId;
use std::time::Duration;
use ic_cdk::api::time;
use base64;
use bs58;



// How often to check for new transactions (in milliseconds)
const MONITORING_INTERVAL_MS: u64 = 60_000; // 1 minute

thread_local! {
    static LAST_CHECKED_TIME: RefCell<u64> = RefCell::new(0);
    static TIMER_ID: RefCell<Option<TimerId>> = RefCell::new(None);
}

#[derive(CandidType, Deserialize, Debug)]
pub struct SignatureResponse {
    pub jsonrpc: String,
    pub result: Vec<SignatureInfo>,
    pub id: u64,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct SignatureInfo {
    pub signature: String,
    pub slot: u64,
    pub err: Option<String>,    // Optional error if the transaction failed
    pub memo: Option<String>,   // Optional memo
    pub blockTime: Option<i64>, // Optional block time
    pub confirmationStatus: Option<String>, // Optional confirmation status
}


#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
pub struct TransferEvent {
    pub sender: String,
    pub recipient: String,
    pub amount: String,
    pub message: String,
    pub timestamp: u64,
    pub signature: String,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Clone)]
pub struct IndexerState {
    pub last_processed_signature: Option<String>,
    pub program_id: String,
    pub events: Vec<TransferEvent>,
    pub last_check_time: u64,
}

static mut INDEXER_STATE: Option<IndexerState> = None;

// Initialize the indexer state
// #[ic_cdk::init]
// fn init() {
//     let state = IndexerState {
//         last_processed_signature: None,
//         program_id: "6GfZF8tuDDNignFFs3uvf1TwSCAvd9rV4d4XSyBXAHiz".to_string(),
//         events: Vec::new(),
//         last_check_time: 0,
//     };
    
//     unsafe {
//         INDEXER_STATE = Some(state);
//     }
    
//     // Start the monitoring timer
//     start_monitoring();
// }

// Helper function to get/update state
fn with_state<F, R>(f: F) -> R
where
    F: FnOnce(&mut IndexerState) -> R,
{
    unsafe {
        if INDEXER_STATE.is_none() {
            INDEXER_STATE = Some(IndexerState {
                last_processed_signature: None,
                program_id: "BBeDW4iezbrsAqVp8DANdr3axW7zun7DdKQyYrAdHDAm".to_string(),
                events: Vec::new(),
                last_check_time: 0,
            });
        }
        
        // Use a simple approach to avoid borrowing issues
        let state_ref = INDEXER_STATE.as_mut().unwrap();
        f(state_ref)
    }
}

#[update]
async fn get_signatures_for_address(address: String) -> Result<Vec<SignatureInfo>, String> {
    let url = "https://api.devnet.solana.com";

    let request_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignaturesForAddress",
        "params": [
            address,
            {
                "limit": 50
            }
        ],
    });
    let request_body_bytes = request_body.to_string().into_bytes();

    let headers = vec![HttpHeader {
        name: "Content-Type".to_string(),
        value: "application/json".to_string(),
    }];

    let request = CanisterHttpRequestArgument {
        url: url.to_string(),
        max_response_bytes: None,
        method: HttpMethod::POST,
        headers,
        body: Some(request_body_bytes),
        transform: None,
    };

    match ic_cdk::api::management_canister::http_request::http_request(request, 21_000_000_000)
        .await
    {
        Ok((response,)) => {
            let response_body = String::from_utf8(response.body)
                .map_err(|_| "Failed to decode response body as UTF-8".to_string())?;

            // Optional: log full response for debugging
            println!("🎯 Raw response body: {:?}", response_body);

            let signature_response: SignatureResponse = serde_json::from_str(&response_body)
                .map_err(|e| format!("❌ Failed to parse response JSON: {}", e))?;

            // ✅ Pretty Print All Signatures Only
            println!("📬 Received Signatures:");
            for sig in &signature_response.result {
                println!("Transaction: {}", sig.signature);
            }

            Ok(signature_response.result)
        }
        Err((rejection_code, msg)) => Err(format!(
            "❌ Request failed: RejectionCode: {:?}, Error: {}",
            rejection_code, msg
        )),
    }
}


#[ic_cdk::update]
async fn get_program_data(signature: String) -> Result<Option<String>, String> {
    let url = "https://api.devnet.solana.com";

    ic_cdk::println!("Processing signature {:?}", signature);

    // Prepare the JSON-RPC payload
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            signature,
            {
                "encoding": "json",
                "commitment": "finalized"
            }
        ]
    });
    let payload_bytes = payload.to_string().into_bytes();

    // Define headers
    let headers = vec![HttpHeader {
        name: "Content-Type".to_string(),
        value: "application/json".to_string(),
    }];

    // Create the HTTP request
    let request = CanisterHttpRequestArgument {
        url: url.to_string(),
        max_response_bytes: None,
        method: HttpMethod::POST,
        headers,
        body: Some(payload_bytes),
        transform: None,
    };

    // Send the HTTP request
    let response = http_request(request, 21_000_000_000)
        .await
        .map_err(|(r, m)| format!("HTTP request failed: RejectionCode: {:?}, Error: {}", r, m))?;

 

    // Parse the response and extract the log messages
    let response_body = String::from_utf8(response.0.body)
        .map_err(|_| "Failed to decode response body as UTF-8".to_string())?;

       ic_cdk::println!("Response: {:?}", response_body);

    let json_response: serde_json::Value = serde_json::from_str(&response_body)
        .map_err(|_| "Failed to parse JSON response".to_string())?;

        ic_cdk::println!("json_response: {:?}", json_response);

    // Get transaction timestamp
    let block_time = json_response["result"]["blockTime"].as_i64();
    
    if let Some(logs) = json_response["result"]["meta"]["logMessages"].as_array() {
        for log in logs.iter().filter_map(|log| log.as_str()) {
            if log.contains("Program data: ") {
                if let Some(encoded_data) = log.split("Program data: ").nth(1) {
                    // Trim any extra whitespace and print the result
                    let encoded_data = encoded_data.trim();
                    ic_cdk::println!("Program data: {}", encoded_data);
                    return Ok(Some(encoded_data.to_string()));
                }
            }
        }
    } else {
        ic_cdk::println!("No log messages found in transaction data.");
    }

    Ok(None)
}





#[derive(Debug, Clone)]
pub struct TokensLockedEvent {
    pub user: String,
    pub admin: String,
    pub destination_address: String,
    pub amount: u64,
    pub mint: String,
    pub timestamp: i64,
}



async fn decode_tokens_locked_event(encoded: String) -> Result<TokensLockedEvent, String> {
    let decoded_bytes = base64::decode(&encoded)
        .map_err(|e| format!("Base64 decode failed: {}", e))?;

    let mut offset = 8; // Skip Anchor's 8-byte event discriminator

    // Helper function to safely read bytes
    fn read_bytes<'a>(data: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8], String> {
        if *offset + len > data.len() {
            return Err(format!(
                "Insufficient data: needed {}, got {}",
                *offset + len, data.len()
            ));
        }
        let result = &data[*offset..*offset + len];
        *offset += len;
        Ok(result)
    }

    // Helper function to safely read u64
    fn read_u64(data: &[u8], offset: &mut usize) -> Result<u64, String> {
        let bytes = read_bytes(data, offset, 8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    // Helper function to safely read i64
    fn read_i64(data: &[u8], offset: &mut usize) -> Result<i64, String> {
        let bytes = read_bytes(data, offset, 8)?;
        Ok(i64::from_le_bytes(bytes.try_into().unwrap()))
    }

    ic_cdk::println!("Total log data length: {}", decoded_bytes.len());
    ic_cdk::println!("Starting parse at offset = 8 (Anchor discriminator)");

    // Read the TokensLocked event fields:
    // pub user: Pubkey,
    // pub admin: Pubkey, 
    // pub destination_address: Pubkey,
    // pub amount: u64,
    // pub mint: Pubkey,
    // pub timestamp: i64,

    let user = bs58::encode(read_bytes(&decoded_bytes, &mut offset, 32)?).into_string();
    let admin = bs58::encode(read_bytes(&decoded_bytes, &mut offset, 32)?).into_string();
    let destination_address = bs58::encode(read_bytes(&decoded_bytes, &mut offset, 32)?).into_string();
    let amount = read_u64(&decoded_bytes, &mut offset)?;
    let mint = bs58::encode(read_bytes(&decoded_bytes, &mut offset, 32)?).into_string();
    let timestamp = read_i64(&decoded_bytes, &mut offset)?;

    ic_cdk::println!("Successfully parsed TokensLocked event fields");

    Ok(TokensLockedEvent {
        user,
        admin,
        destination_address,
        amount,
        mint,
        timestamp,
    })
}

#[ic_cdk::update]
async fn process_tokens_locked_event(encoded_data: String) -> Result<(), String> {
    match decode_tokens_locked_event(encoded_data).await {
        Ok(event) => {
            ic_cdk::println!("=== TOKENS LOCKED EVENT ===");
            ic_cdk::println!("User: {}", event.user);
            ic_cdk::println!("Admin: {}", event.admin);
            ic_cdk::println!("Destination Address: {}", event.destination_address);
            ic_cdk::println!("Amount: {}", event.amount);
            ic_cdk::println!("Mint: {}", event.mint);
            ic_cdk::println!("Timestamp: {}", event.timestamp);
            Ok(())
        },
        Err(err) => {
            ic_cdk::println!("Error decoding TokensLocked event: {}", err);
            Err(err)
        }
    }
}





#[ic_cdk::update]
async fn index_transactions() -> Result<Vec<TransferEvent>, String> {
    let program_id = with_state(|state| state.program_id.clone());
    let last_sig = with_state(|state| state.last_processed_signature.clone());
      
      ic_cdk::println!("program_id: {}", program_id);
    // Get signatures for the program
    let signatures = get_signatures_for_address(program_id).await?;
    ic_cdk::println!("SIGNATURES: {:?}", signatures);
    
    // Process transactions in reverse order (newest first)
    let mut new_events = Vec::new();
    let mut newest_signature: Option<String> = None;
    
    // Track the newest signature we've seen
    if let Some(sig) = signatures.first() {
        newest_signature = Some(sig.signature.clone());
    }
    
    // If we have a last processed signature, only process transactions after it
    let mut should_process = last_sig.is_none();
    
    for sig_info in signatures {
        // Skip until we find the last processed signature
        if let Some(ref last_processed) = last_sig {
            if !should_process {
                if sig_info.signature == *last_processed {
                    should_process = true; // Found our marker, start processing after this
                }
                continue;
            }
        }
        
        // Process this transaction
        if let Ok(Some(encoded_data)) = get_program_data(sig_info.signature.clone()).await {
            // Decode as TokensLocked event
            if let Ok(_) = process_tokens_locked_event(encoded_data).await {
                ic_cdk::println!("Indexed new TokensLocked event with signature: {}", sig_info.signature);
            } else {
                ic_cdk::println!("Failed to decode TokensLocked event for signature: {}", sig_info.signature);
            }
        }
    }
    
    // Update our state with the newest signature
    if let Some(sig) = newest_signature {
        with_state(|state| {
            state.last_processed_signature = Some(sig);
            state.last_check_time = time() / 1_000_000;
        });
    }
    
    Ok(new_events)
}

// Start the monitoring process
#[update]
pub fn start_monitoring() {
    let timer_id = ic_cdk_timers::set_timer_interval(Duration::from_millis(MONITORING_INTERVAL_MS), || {
        ic_cdk::spawn(async {
            let current_time = time() / 1_000_000;
            let last_check_time = with_state(|state| state.last_check_time);
            
            // Only check if enough time has passed (to avoid redundant calls)
            if current_time > last_check_time + 30 { // At least 30 seconds between checks
                ic_cdk::println!("Checking for new transactions...");
                match index_transactions().await {
                    Ok(events) => {
                        if !events.is_empty() {
                            ic_cdk::println!("Indexed {} new events", events.len());
                        } else {
                            ic_cdk::println!("No new events found");
                        }
                    },
                    Err(e) => {
                        ic_cdk::println!("Error indexing transactions: {}", e);
                    }
                }
            }
        });
    });
    
    TIMER_ID.with(|id| {
        // Clear any existing timer first
        if let Some(old_id) = *id.borrow() {
            ic_cdk_timers::clear_timer(old_id);
        }
        // Set the new timer
        *id.borrow_mut() = Some(timer_id);
    });
    
    ic_cdk::println!("Solana monitoring started for address: {}", 
        with_state(|state| state.program_id.clone()));
}


#[ic_cdk::update]
pub fn stop_monitoring() -> String {
    TIMER_ID.with(|timer_id| {
        if let Some(id) = *timer_id.borrow() {
            ic_cdk_timers::clear_timer(id);
            *timer_id.borrow_mut() = None;
        }
    });
    
    "Solana monitoring stopped".to_string()
}

#[ic_cdk::query]
pub fn get_all_events() -> Vec<TransferEvent> {
    with_state(|state| state.events.clone())
}

#[ic_cdk::query]
pub fn get_latest_events(count: u32) -> Vec<TransferEvent> {
    with_state(|state| {
        let start = if state.events.len() > count as usize {
            state.events.len() - count as usize
        } else {
            0
        };
        state.events[start..].to_vec()
    })
}

#[ic_cdk::query]
pub fn get_indexer_state() -> IndexerState {
    with_state(|state| state.clone())
}

#[ic_cdk::update]
pub fn reset_indexer() {
    with_state(|state| {
        state.last_processed_signature = None;
        state.events.clear();
        state.last_check_time = 0;
    });
}

#[ic_cdk::update]
pub fn set_program_id(program_id: String) {
    with_state(|state| {
        state.program_id = program_id;
        state.last_processed_signature = None; // Reset tracking when changing program
    });
}

