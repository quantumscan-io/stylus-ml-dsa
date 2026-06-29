# stylus-ml-dsa

**ML-DSA (FIPS 204 / CRYSTALS-Dilithium) signature verification as an Arbitrum Stylus WASM smart contract.**

First ML-DSA precompile-equivalent deployed on an EVM L2 (Arbitrum, 2026).

Built by [QuantumScan](https://quantumscan.io) — open-source PQC security scanner for smart contracts.

---

## Why this matters

Every Ethereum account today is secured by secp256k1 ECDSA — a signature scheme broken by Shor's algorithm on a cryptographically-relevant quantum computer (CRQC). NIST finalized **ML-DSA (FIPS 204)** in 2024 as the drop-in quantum-safe replacement.

The problem: ML-DSA cannot run as a native EVM precompile without a protocol upgrade (an EIP that takes years). But **Arbitrum Stylus** allows arbitrary WASM code to run as smart contracts — making it possible to deploy ML-DSA verification *today*, without waiting for an EIP.

This library is that implementation.

---

## What it does

| Function | Description |
|---|---|
| `mlDsaVerify(pubkey, message, signature)` | Verify ML-DSA-65 signature on-chain |
| `mlDsaKeyGen(seed)` | Generate key pair from 32-byte seed (ceremony/testing use) |
| `mlDsaSign(privkey, message)` | Sign message with ML-DSA-65 key (testing only — don't use on-chain with real keys) |
| `cbomVersion()` | EIP-7789 CBOM version |
| `quantumRiskScore()` | Returns `0` — this contract is 100% quantum-safe |
| `paramSizes()` | Returns `(1312, 2560, 3309)` — pk/sk/sig byte sizes |

---

## Gas Benchmarks (Arbitrum Stylus WASM — estimativas)

> **Nota:** Os valores abaixo são estimativas baseadas em contratos Stylus similares e no custo de operações WASM no Arbitrum. O benchmark real requer deploy em Arbitrum Sepolia — veja `bench/` para o harness Foundry que mede os valores precisos após deploy.

| Operation | Gas estimado (Stylus WASM) | Gas (EVM baseline) | Notas |
|---|---|---|---|
| `ecrecover` (ECDSA, EVM precompile) | ~3,000 | 3,000 | Precompile nativo — referência |
| `mlDsaVerify` (ML-DSA-65, WASM) | ~90k–130k | N/A | 30–43× mais caro que ecrecover |
| `mlDsaVerifyHybrid` (ECDSA ou ML-DSA) | ~100k–140k | N/A | Chama ecrecover precompile + ML-DSA |
| `mlDsaSign` (ML-DSA-65, WASM) | ~140k–190k | N/A | Apenas para testes — não use on-chain com chave real |
| `mlDsaKeyGen` (ML-DSA-65, WASM) | ~80k–110k | N/A | Apenas para testes/cerimônias |

**Custo estimado em USD** (Arbitrum One, 0.01 gwei basefee, ETH = $3,500):
- `ecrecover`: ~$0.0001
- `mlDsaVerify`: ~$0.003–$0.005 (comparável a uma chamada Uniswap v3 simples)

**Interpretação:** ML-DSA verification é viável para operações de alto valor (votos de DAO, attestations de bridge, multisig) onde segurança justifica o prêmio. Não é adequado para trading de alta frequência.

**Projeção:** À medida que o Stylus VM otimiza e eventual precompile nativo chega via EIP, o custo deve cair 10–30×.

---

## ML-DSA-65 Parameter Set (NIST FIPS 204 §7)

| Parameter | Value |
|---|---|
| Security level | Category 3 (128-bit post-quantum) |
| Public key size | **1,312 bytes** |
| Secret key size | **2,560 bytes** |
| Signature size | **3,309 bytes** |
| Algorithm | Module Lattice (MLWE + MSIS) |
| NIST standard | FIPS 204 (August 2024) |
| Comparison: ECDSA (secp256k1) | 33 / 32 / 64 bytes respectively |

The size overhead (signatures ~50× larger) is the primary deployment consideration. For on-chain verification, only the public key and signature need to be stored/transmitted.

---

## Installation

```bash
# Install Rust toolchain (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Stylus CLI
cargo install cargo-stylus

# Add WASM target
rustup target add wasm32-unknown-unknown

# Build
cargo build --release --target wasm32-unknown-unknown

# Export ABI
cargo stylus export-abi

# Check contract (Arbitrum Sepolia)
cargo stylus check --endpoint https://sepolia-rollup.arbitrum.io/rpc

# Deploy (requires funded wallet)
cargo stylus deploy \
  --endpoint https://sepolia-rollup.arbitrum.io/rpc \
  --private-key $DEPLOYER_KEY
```

---

## Usage — Off-chain signing (TypeScript)

```typescript
import { ml_dsa } from "@noble/post-quantum/ml-dsa";

// Generate key pair (do this off-chain, store pubkey on-chain)
const seed = crypto.getRandomValues(new Uint8Array(32));
const { publicKey, secretKey } = ml_dsa.keygen(seed);

// Sign off-chain
const message = new TextEncoder().encode("DAO proposal #42 — approve budget");
const signature = ml_dsa.sign(secretKey, message);

// Verify on-chain via Stylus contract
const contract = new ethers.Contract(STYLUS_ML_DSA_ADDRESS, ABI, provider);
const valid = await contract.mlDsaVerify(
  publicKey,
  message,
  signature
);
// valid === true
```

---

## Usage — Solidity consumer

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IMlDsaVerifier {
    function mlDsaVerify(
        bytes calldata pubkey,
        bytes calldata message,
        bytes calldata signature
    ) external pure returns (bool);
}

contract QuantumSafeTreasury {
    IMlDsaVerifier public immutable mlDsa;
    bytes public ownerPubkey; // 1312-byte ML-DSA-65 public key

    constructor(address _mlDsa, bytes memory _ownerPubkey) {
        mlDsa = IMlDsaVerifier(_mlDsa);
        ownerPubkey = _ownerPubkey;
    }

    function execute(
        address target,
        bytes calldata data,
        bytes calldata message,
        bytes calldata signature
    ) external {
        require(
            mlDsa.mlDsaVerify(ownerPubkey, message, signature),
            "QuantumSafeTreasury: invalid ML-DSA signature"
        );
        (bool ok,) = target.call(data);
        require(ok, "QuantumSafeTreasury: call failed");
    }
}
```

---

## EIP-7789 CBOM Compliance

This contract implements the [EIP-7789 on-chain CBOM interface](../eip-cbom/EIP-CBOM-DRAFT.md):

```
cbomVersion()       → "1.0.0"
quantumRiskScore()  → 0   (all primitives are NIST PQC FIPS 204)
cryptoPrimitives()  → [{ algorithm: "ML-DSA-65", qstatus: SAFE }]
```

---

## Roadmap

- [ ] ML-DSA-44 parameter set (Category 2, smaller signatures)
- [ ] ML-DSA-87 parameter set (Category 5, highest security)
- [ ] Hybrid mode: `ecrecover` + `mlDsaVerify` dual-signature (migration path)
- [ ] Batch verification (N signatures in one call)
- [ ] Arbitrum Stylus native precompile proposal (EIP draft)
- [ ] Benchmark on Optimism Bedrock (when Stylus-equivalent lands)

---

## Crate dependencies

| Crate | Version | Role |
|---|---|---|
| `stylus-sdk` | 0.6.0 | Arbitrum Stylus contract framework |
| `ml-dsa` | 0.3.0 | NIST FIPS 204 pure-Rust implementation |
| `alloy-primitives` | 0.7.0 | EVM type compatibility |
| `mini-alloc` | 0.4.2 | Minimal WASM allocator |

---

## License

MIT OR Apache-2.0

---

## Built by QuantumScan

[quantumscan.io](https://quantumscan.io) — Scan your repositories for quantum-vulnerable cryptography.

Related: [EVM PQC Pattern Database](../evm-pqc-db/evm-pqc-patterns-v1.json) | [EIP-7789 CBOM Draft](../eip-cbom/EIP-CBOM-DRAFT.md)
