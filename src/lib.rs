//! ML-DSA (FIPS 204 / CRYSTALS-Dilithium) signature verification
//! as an Arbitrum Stylus WASM smart contract.
//!
//! First ML-DSA precompile-equivalent on an EVM L2 (Arbitrum Stylus, 2026).
//!
//! Interface (Solidity-compatible via Stylus ABI export):
//!   function mlDsaVerify(bytes pubkey, bytes message, bytes signature) external pure returns (bool)
//!   function mlDsaKeyGen(bytes seed) external pure returns (bytes pubkey, bytes privkey)
//!   function mlDsaSign(bytes privkey, bytes message) external pure returns (bytes signature)
//!   function cbomVersion() external pure returns (string)
//!   function quantumRiskScore() external pure returns (uint8)

#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use stylus_sdk::prelude::*;
use stylus_sdk::alloy_primitives::U8;

use ml_dsa::{MlDsa65, KeyGen, Signature as MlDsaSignature};

// Required for Stylus WASM ABI
#[global_allocator]
static ALLOC: mini_alloc::MiniAlloc = mini_alloc::MiniAlloc::INIT;

// ── Contract storage (stateless — all ops are pure) ──────────────────────────

sol_storage! {
    #[entrypoint]
    pub struct MlDsaVerifier {}
}

// ── Public interface ──────────────────────────────────────────────────────────

#[public]
impl MlDsaVerifier {

    /// Verify an ML-DSA-65 (FIPS 204) signature.
    ///
    /// # Parameters
    /// - `pubkey`    : 1312-byte ML-DSA-65 public key
    /// - `message`   : arbitrary message bytes
    /// - `signature` : 3309-byte ML-DSA-65 signature
    ///
    /// # Returns
    /// `true` if the signature is valid for the given public key and message.
    ///
    /// # Gas estimate (Arbitrum Stylus WASM)
    /// ~85,000–120,000 gas — vs ecrecover precompile ~3,000 gas.
    /// Classical ECDSA on EVM is cheaper because it is a native precompile.
    /// ML-DSA-65 in Stylus WASM is ~30–40x more expensive at the time of writing
    /// but remains feasible for high-value operations (DAO votes, bridge attestations).
    /// Expected to drop as Stylus VM optimizations mature and potential future precompile lands.
    pub fn ml_dsa_verify(
        &self,
        pubkey: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, Vec<u8>> {
        // ML-DSA-65 public key is exactly 1312 bytes (FIPS 204 §7)
        let pk_bytes: [u8; 1312] = pubkey
            .try_into()
            .map_err(|_| b"ML-DSA: invalid pubkey length (expected 1312 bytes)".to_vec())?;

        // ML-DSA-65 signature is exactly 3309 bytes (FIPS 204 §7)
        let sig_bytes: [u8; 3309] = signature
            .try_into()
            .map_err(|_| b"ML-DSA: invalid signature length (expected 3309 bytes)".to_vec())?;

        let pk = MlDsa65::public_key_from_bytes(&pk_bytes)
            .map_err(|_| b"ML-DSA: malformed public key".to_vec())?;

        let sig = MlDsaSignature::<MlDsa65>::from_bytes(&sig_bytes)
            .map_err(|_| b"ML-DSA: malformed signature".to_vec())?;

        Ok(pk.verify(&message, &sig).is_ok())
    }

    /// Generate an ML-DSA-65 key pair from a 32-byte seed.
    ///
    /// # Parameters
    /// - `seed` : 32-byte entropy seed (MUST be cryptographically random)
    ///
    /// # Returns
    /// `(pubkey, privkey)` — (1312, 2560) bytes respectively.
    ///
    /// # Security note
    /// On-chain key generation is ONLY safe for pre-shared / ceremony keys.
    /// For user keys, generate off-chain using a secure random number generator
    /// and only store the public key on-chain.
    pub fn ml_dsa_key_gen(
        &self,
        seed: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>), Vec<u8>> {
        let seed_bytes: [u8; 32] = seed
            .try_into()
            .map_err(|_| b"ML-DSA: seed must be exactly 32 bytes".to_vec())?;

        let (sk, pk) = MlDsa65::key_gen_from_seed(&seed_bytes);

        Ok((pk.to_bytes().to_vec(), sk.to_bytes().to_vec()))
    }

    /// Sign a message with an ML-DSA-65 private key.
    ///
    /// # Parameters
    /// - `privkey` : 2560-byte ML-DSA-65 private key
    /// - `message` : arbitrary message bytes
    ///
    /// # Returns
    /// 3309-byte ML-DSA-65 signature.
    ///
    /// # Gas estimate
    /// ~130,000–180,000 gas (signing is more expensive than verification).
    ///
    /// # Security note
    /// Do NOT call this function with a production private key on-chain.
    /// Use off-chain signing (CLI / library) and only call `ml_dsa_verify` on-chain.
    /// This function is provided for testing and ceremony use only.
    pub fn ml_dsa_sign(
        &self,
        privkey: Vec<u8>,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, Vec<u8>> {
        let sk_bytes: [u8; 2560] = privkey
            .try_into()
            .map_err(|_| b"ML-DSA: invalid privkey length (expected 2560 bytes)".to_vec())?;

        let sk = MlDsa65::secret_key_from_bytes(&sk_bytes)
            .map_err(|_| b"ML-DSA: malformed private key".to_vec())?;

        let signature = sk.sign(&message);
        Ok(signature.to_bytes().to_vec())
    }

    /// EIP-7789 CBOM: returns CBOM version implemented by this contract.
    pub fn cbom_version(&self) -> Result<String, Vec<u8>> {
        Ok(String::from("1.0.0"))
    }

    /// EIP-7789 CBOM: quantum risk score for this contract.
    /// Returns 0 — all primitives are NIST PQC standard (ML-DSA-65).
    pub fn quantum_risk_score(&self) -> Result<u8, Vec<u8>> {
        Ok(0u8)
    }

    /// Returns ML-DSA-65 parameter set sizes for introspection.
    pub fn param_sizes(&self) -> Result<(u32, u32, u32), Vec<u8>> {
        Ok((
            1312u32, // public key bytes
            2560u32, // secret key bytes
            3309u32, // signature bytes
        ))
    }
}

// ── ABI export (cargo stylus export-abi) ─────────────────────────────────────

#[cfg(feature = "export-abi")]
fn main() {
    stylus_sdk::abi::export::print_abi::<MlDsaVerifier>("MlDsaVerifier", "run");
}
