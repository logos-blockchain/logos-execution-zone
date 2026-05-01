use sharks::{Sharks, Share};
use crate::types::NullifierSecretKey;

/// Splits `NullifierSecretKey` (NSK) into `M` parts.
/// `N` (threshold) parts are required to reconstruct it.
/// This operation is performed over the Galois Field GF(2^8).
pub fn split_secret(
    secret: &NullifierSecretKey,
    threshold_n: u32,
    total_m: u32,
) -> Result<Vec<Vec<u8>>, &'static str> {
    if threshold_n > total_m {
        return Err("Threshold (N) cannot exceed the total number of moderators (M)");
    }
    if threshold_n < 1 || threshold_n > 255 {
        return Err("Threshold must be between 1 and 255");
    }

    // Initialize the secret-sharing entity with threshold N
    // Sharks performs GF(256) math behind the scenes
    let sharks = Sharks(threshold_n as u8);
    
    // The dealer will split the secret byte by byte
    // and generate coordinate points (X, Y) deterministically/randomly
    let dealer = sharks.dealer(secret.as_slice());

    // Take M shares.
    // The Vec<u8> output format automatically packs the X coordinate (1 byte)
    // and Y coordinate (32 bytes) from each share.
    let shares: Vec<Vec<u8>> = dealer
        .take(total_m as usize)
        .map(|share| Vec::from(&share))
        .collect();

    Ok(shares)
}

/// Reconstructs `NullifierSecretKey` using at least `N` shares.
/// This function performs Lagrange interpolation over a finite field.
pub fn recover_secret(
    shares_bytes: &[Vec<u8>],
    threshold_n: u32,
) -> Result<NullifierSecretKey, &'static str> {
    if shares_bytes.len() < threshold_n as usize {
        return Err("The number of shares is below the required threshold");
    }

    let sharks = Sharks(threshold_n as u8);

    // Parse the byte arrays back into mathematical Share objects (X and Y coordinates)
    let valid_shares: Vec<Share> = shares_bytes
        .iter()
        .filter_map(|b| Share::try_from(b.as_slice()).ok())
        .collect();

    if valid_shares.len() < threshold_n as usize {
        return Err("Some shares are corrupt/invalid. Reconstruction aborted");
    }

    // Perform Lagrange interpolation to find f(0) on the GF(256) graph
    let secret_vec = sharks.recover(&valid_shares)
        .map_err(|_| "Polynomial interpolation failed. Share is invalid or does not match")?;

    if secret_vec.len() != 32 {
        return Err("The reconstructed secret length does not match NSK (32 bytes)");
    }

    // Convert back into NSSA's built-in NullifierSecretKey format
    let mut recovered_nsk = [0u8; 32];
    recovered_nsk.copy_from_slice(&secret_vec);

    Ok(recovered_nsk)
}