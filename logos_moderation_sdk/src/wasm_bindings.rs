use wasm_bindgen::prelude::*;
use serde_wasm_bindgen::{to_value, from_value};

use crate::clients::member::MemberClient;
use crate::clients::moderator::ModeratorClient;
use crate::clients::aggregator::SlashAggregator;
use crate::types::{EncryptedSharePerPost, ModerationCertificate};

// WRAPPER FOR MODERATOR CLIENT
#[wasm_bindgen]
pub struct WasmModeratorClient {
    inner: ModeratorClient,
}

#[wasm_bindgen]
impl WasmModeratorClient {
    #[wasm_bindgen(constructor)]
    pub fn new(privkey_js: &[u8]) -> Result<WasmModeratorClient, JsValue> {
        if privkey_js.len() != 32 {
            return Err(JsValue::from_str("Private key must be 32 bytes"));
        }
        let mut privkey = [0u8; 32];
        privkey.copy_from_slice(privkey_js);

        Ok(WasmModeratorClient {
            inner: ModeratorClient::new(privkey),
        })
    }

    #[wasm_bindgen]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().to_vec()
    }

    #[wasm_bindgen]
    pub fn issue_strike_wasm(
        &self,
        tracing_tag_js: &[u8],
        encrypted_share_js: &JsValue,
        moderator_index: u32,
    ) -> Result<JsValue, JsValue> {
        let mut tracing_tag = [0u8; 32];
        tracing_tag.copy_from_slice(tracing_tag_js);

        // Deserialize the JSON object (EncryptedSharePerPost) from the frontend
        let encrypted_share: EncryptedSharePerPost = from_value(encrypted_share_js.clone())
            .map_err(|e| JsValue::from_str(&format!("Invalid encrypted share format: {}", e)))?;

        let certificate = self.inner.issue_strike(tracing_tag, &encrypted_share, moderator_index)
            .map_err(|e| JsValue::from_str(e))?;

        // Return ModerationCertificate as JSON
        to_value(&certificate).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

// WRAPPER FOR SLASH AGGREGATOR
#[wasm_bindgen]
pub struct WasmSlashAggregator {
    inner: SlashAggregator,
}

#[wasm_bindgen]
impl WasmSlashAggregator {
    #[wasm_bindgen(constructor)]
    pub fn new(
        n_threshold: u32, 
        k_strikes: u32, 
        moderator_pubkeys_js: &JsValue
    ) -> Result<WasmSlashAggregator, JsValue> {
        // Deserialize array of pubkeys
        let mod_pubkeys: Vec<[u8; 32]> = from_value(moderator_pubkeys_js.clone())
            .map_err(|e| JsValue::from_str(&format!("Invalid pubkeys array: {}", e)))?;

        Ok(WasmSlashAggregator {
            inner: SlashAggregator::new(n_threshold, k_strikes, &mod_pubkeys),
        })
    }

    #[wasm_bindgen]
    pub fn reconstruct_strike_wasm(
        &self,
        tracing_tag_js: &[u8],
        certificates_js: &JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let mut tracing_tag = [0u8; 32];
        tracing_tag.copy_from_slice(tracing_tag_js);

        let certificates: Vec<ModerationCertificate> = from_value(certificates_js.clone())
            .map_err(|e| JsValue::from_str(&format!("Invalid certificates array: {}", e)))?;

        let s_post = self.inner.reconstruct_strike(&tracing_tag, &certificates)
            .map_err(|e| JsValue::from_str(e))?;

        Ok(s_post.to_vec())
    }

    #[wasm_bindgen]
    pub fn reconstruct_nsk_wasm(
        &self,
        accumulated_strikes_js: &JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        // The frontend will send an array of arrays: [[x_index, ...32_byte_s_post], [...]]
        // We need to parse this into the format expected by the backend: &[(u8, [u8; 32])]
        let raw_strikes: Vec<Vec<u8>> = from_value(accumulated_strikes_js.clone())
            .map_err(|e| JsValue::from_str(&format!("Invalid accumulated strikes format: {}", e)))?;

        let mut parsed_strikes = Vec::new();
        for strike_data in raw_strikes {
            if strike_data.len() != 33 {
                return Err(JsValue::from_str("Each strike must be exactly 33 bytes (1 byte X + 32 bytes S_post)"));
            }
            let x_index = strike_data[0];
            let mut s_post = [0u8; 32];
            s_post.copy_from_slice(&strike_data[1..33]);
            parsed_strikes.push((x_index, s_post));
        }

        let nsk = self.inner.reconstruct_nsk(&parsed_strikes)
            .map_err(|e| JsValue::from_str(e))?;

        Ok(nsk.to_vec())
    }
}

// WRAPPER FOR MEMBER CLIENT
#[wasm_bindgen]
pub struct WasmMemberClient {
    inner: MemberClient,
}

#[wasm_bindgen]
impl WasmMemberClient {
    // Constructor to be called in React: `new WasmMemberClient(nsk_array, 3)`
    #[wasm_bindgen(constructor)]
    pub fn new(nsk_js: &[u8], k_strikes: u32) -> Result<WasmMemberClient, JsValue> {
        if nsk_js.len() != 32 {
            return Err(JsValue::from_str("NSK must be 32 bytes"));
        }
        let mut nsk = [0u8; 32];
        nsk.copy_from_slice(nsk_js);

        Ok(WasmMemberClient {
            inner: MemberClient::new(nsk, k_strikes),
        })
    }

    // prepare_post function that returns a JSON object to JavaScript
    #[wasm_bindgen]
    pub fn prepare_post_wasm(
        &mut self,
        message: &str, 
        post_salt_js: &[u8],
        moderator_pubkeys_js: &JsValue, 
        n_moderator_threshold: u32,
    ) -> Result<JsValue, JsValue> {
        
        let mut post_salt = [0u8; 32];
        post_salt.copy_from_slice(post_salt_js);

        // Deserialize pubkeys from JS
        let mod_pubkeys: Vec<[u8; 32]> = from_value(moderator_pubkeys_js.clone())
            .map_err(|e| JsValue::from_str(&format!("Invalid pubkeys: {}", e)))?;

        // Call the original Rust function
        let payload = self.inner.prepare_post(
            message.as_bytes(),
            &post_salt,
            &mod_pubkeys,
            n_moderator_threshold
        ).map_err(|e| JsValue::from_str(e))?;

        // Return as a JSON object to JS
        to_value(&payload).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}