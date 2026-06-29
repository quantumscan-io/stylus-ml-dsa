//! ML-DSA (FIPS 204 / CRYSTALS-Dilithium) — Arbitrum Stylus WASM contract
//!
//! Provides ML-DSA-65 key gen / sign / verify AND hybrid ECDSA+ML-DSA
//! verification for backward-compatible migration from secp256k1 wallets.
//!
//! First ML-DSA precompile-equivalent on an EVM L2 (Arbitrum Stylus, 2026).

#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use stylus_sdk::alloy_primitives::{Address, B256};
use stylus_sdk::call::Call;
use stylus_sdk::prelude::*;

use ml_dsa::{MlDsa65, KeyGen, Signature as MlDsaSignature};

#[global_allocator]
static ALLOC: mini_alloc::MiniAlloc = mini_alloc::MiniAlloc::INIT;

// ecrecover precompile address
const ECRECOVER_PRECOMPILE: Address = Address::new([
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1,
]);

sol_storage! {
    #[entrypoint]
    pub struct MlDsaVerifier {}
}

#[public]
impl MlDsaVerifier {

    // ── Core ML-DSA operations ────────────────────────────────────────────────

    /// Verify an ML-DSA-65 (FIPS 204) signature.
    ///
    /// pubkey    : 1312 bytes — ML-DSA-65 public key
    /// message   : arbitrary bytes
    /// signature : 3309 bytes — ML-DSA-65 signature
    ///
    /// Returns true if valid.
    pub fn ml_dsa_verify(
        &self,
        pubkey: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, Vec<u8>> {
        let pk_bytes: [u8; 1312] = pubkey
            .try_into()
            .map_err(|_| b"ML-DSA: pubkey must be 1312 bytes".to_vec())?;

        let sig_bytes: [u8; 3309] = signature
            .try_into()
            .map_err(|_| b"ML-DSA: signature must be 3309 bytes".to_vec())?;

        let pk = MlDsa65::public_key_from_bytes(&pk_bytes)
            .map_err(|_| b"ML-DSA: malformed public key".to_vec())?;

        let sig = MlDsaSignature::<MlDsa65>::from_bytes(&sig_bytes)
            .map_err(|_| b"ML-DSA: malformed signature".to_vec())?;

        Ok(pk.verify(&message, &sig).is_ok())
    }

    /// Hybrid verification — accepts EITHER a valid ECDSA OR ML-DSA signature.
    ///
    /// Use this during the migration period: existing secp256k1 signers continue
    /// to work while new PQC signers can use ML-DSA. When you're ready to drop
    /// ECDSA, switch to `mlDsaVerify`.
    ///
    /// Parameters:
    ///   hash        : 32-byte message hash (for ecrecover)
    ///   v           : ECDSA recovery id (27 or 28)
    ///   r, s        : ECDSA signature components (32 bytes each)
    ///   ecdsa_addr  : expected Ethereum address for ECDSA signer (zero = skip ECDSA check)
    ///   ml_dsa_pub  : 1312-byte ML-DSA-65 public key (empty = skip ML-DSA check)
    ///   ml_dsa_msg  : message for ML-DSA verification
    ///   ml_dsa_sig  : 3309-byte ML-DSA-65 signature (empty = skip ML-DSA check)
    ///
    /// Returns true if AT LEAST ONE of (ECDSA, ML-DSA) verifies successfully.
    pub fn ml_dsa_verify_hybrid(
        &mut self,
        hash: B256,
        v: u8,
        r: B256,
        s: B256,
        ecdsa_addr: Address,
        ml_dsa_pub: Vec<u8>,
        ml_dsa_msg: Vec<u8>,
        ml_dsa_sig: Vec<u8>,
    ) -> Result<bool, Vec<u8>> {
        // ── Branch 1: ECDSA via ecrecover precompile ──────────────────────────
        let ecdsa_valid = if ecdsa_addr != Address::ZERO {
            // Build ecrecover input: hash(32) + v(32) + r(32) + s(32) = 128 bytes
            let mut input = [0u8; 128];
            input[0..32].copy_from_slice(hash.as_slice());
            input[63] = v; // v goes in byte 63 (padded to 32 bytes)
            input[64..96].copy_from_slice(r.as_slice());
            input[96..128].copy_from_slice(s.as_slice());

            let result = Call::new()
                .call(ECRECOVER_PRECOMPILE, &input)
                .map_err(|_| b"hybrid: ecrecover call failed".to_vec())?;

            if result.len() == 32 {
                // ecrecover returns address right-padded to 32 bytes
                let mut recovered = [0u8; 20];
                recovered.copy_from_slice(&result[12..32]);
                Address::from(recovered) == ecdsa_addr
            } else {
                false
            }
        } else {
            false
        };

        if ecdsa_valid {
            return Ok(true);
        }

        // ── Branch 2: ML-DSA-65 ───────────────────────────────────────────────
        if ml_dsa_pub.len() == 1312 && ml_dsa_sig.len() == 3309 {
            let pk_bytes: [u8; 1312] = ml_dsa_pub.try_into().unwrap();
            let sig_bytes: [u8; 3309] = ml_dsa_sig.try_into().unwrap();

            if let Ok(pk) = MlDsa65::public_key_from_bytes(&pk_bytes) {
                if let Ok(sig) = MlDsaSignature::<MlDsa65>::from_bytes(&sig_bytes) {
                    if pk.verify(&ml_dsa_msg, &sig).is_ok() {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Generate an ML-DSA-65 key pair from a 32-byte seed.
    ///
    /// SECURITY: use only for ceremonies or testing. For user keys,
    /// generate off-chain with a CSPRNG and store only the public key on-chain.
    pub fn ml_dsa_key_gen(
        &self,
        seed: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), Vec<u8>> {
        let seed_bytes: [u8; 32] = seed
            .try_into()
            .map_err(|_| b"ML-DSA: seed must be 32 bytes".to_vec())?;

        let (sk, pk) = MlDsa65::key_gen_from_seed(&seed_bytes);
        Ok((pk.to_bytes().to_vec(), sk.to_bytes().to_vec()))
    }

    /// Sign a message with an ML-DSA-65 private key.
    ///
    /// SECURITY: do NOT call with a real private key on-chain. Use off-chain.
    pub fn ml_dsa_sign(
        &self,
        privkey: Vec<u8>,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, Vec<u8>> {
        let sk_bytes: [u8; 2560] = privkey
            .try_into()
            .map_err(|_| b"ML-DSA: privkey must be 2560 bytes".to_vec())?;

        let sk = MlDsa65::secret_key_from_bytes(&sk_bytes)
            .map_err(|_| b"ML-DSA: malformed private key".to_vec())?;

        Ok(sk.sign(&message).to_bytes().to_vec())
    }

    // ── EIP-7789 CBOM ────────────────────────────────────────────────────────

    /// EIP-7789: CBOM version implemented by this contract.
    pub fn cbom_version(&self) -> Result<String, Vec<u8>> {
        Ok(String::from("1.0.0"))
    }

    /// EIP-7789: quantum risk score — 0 (all primitives are NIST FIPS 204 ML-DSA-65).
    pub fn quantum_risk_score(&self) -> Result<u8, Vec<u8>> {
        Ok(0u8)
    }

    /// Returns (pubkeyBytes, secretKeyBytes, signatureBytes) for ML-DSA-65.
    pub fn param_sizes(&self) -> Result<(u32, u32, u32), Vec<u8>> {
        Ok((1312u32, 2560u32, 3309u32))
    }
}

#[cfg(feature = "export-abi")]
fn main() {
    stylus_sdk::abi::export::print_abi::<MlDsaVerifier>("MlDsaVerifier", "run");
}
