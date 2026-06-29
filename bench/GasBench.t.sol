// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Foundry gas benchmark harness for stylus-ml-dsa
// Run after deploying MlDsaVerifier to Arbitrum Sepolia:
//
//   STYLUS_ADDR=0x... forge test --fork-url $ARB_SEPOLIA_RPC -vv --gas-report
//
// Results go in README.md gas table.

import "forge-std/Test.sol";

interface IMlDsaVerifier {
    function mlDsaVerify(bytes calldata pubkey, bytes calldata message, bytes calldata signature)
        external pure returns (bool);
    function mlDsaVerifyHybrid(
        bytes32 hash, uint8 v, bytes32 r, bytes32 s,
        address ecdsaAddr,
        bytes calldata mlDsaPub, bytes calldata mlDsaMsg, bytes calldata mlDsaSig
    ) external returns (bool);
    function mlDsaKeyGen(bytes calldata seed) external pure returns (bytes memory pubkey, bytes memory privkey);
    function mlDsaSign(bytes calldata privkey, bytes calldata message) external pure returns (bytes memory);
    function paramSizes() external pure returns (uint32, uint32, uint32);
}

contract GasBench is Test {
    IMlDsaVerifier verifier;
    address constant ECRECOVER = address(1);

    // Test vectors — replace with real FIPS 204 test vectors before benchmarking
    bytes constant TEST_PK   = new bytes(1312); // zeroed placeholder
    bytes constant TEST_SIG  = new bytes(3309); // zeroed placeholder
    bytes constant TEST_MSG  = "QuantumScan benchmark message 2026";
    bytes constant TEST_SEED = new bytes(32);   // zeroed placeholder

    function setUp() public {
        address stylusAddr = vm.envAddress("STYLUS_ADDR");
        verifier = IMlDsaVerifier(stylusAddr);
    }

    function test_GasVerify() public {
        uint256 gasBefore = gasleft();
        verifier.mlDsaVerify(TEST_PK, TEST_MSG, TEST_SIG);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("mlDsaVerify gas:", gasUsed);
    }

    function test_GasHybridEcdsa() public {
        // Test the ECDSA branch of hybrid verify
        bytes32 hash = keccak256(TEST_MSG);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, hash); // anvil key #1
        address signer = vm.addr(1);

        uint256 gasBefore = gasleft();
        verifier.mlDsaVerifyHybrid(
            hash, v, r, s, signer,
            new bytes(0), new bytes(0), new bytes(0) // skip ML-DSA branch
        );
        uint256 gasUsed = gasBefore - gasleft();
        console.log("mlDsaVerifyHybrid (ECDSA branch) gas:", gasUsed);
    }

    function test_GasKeyGen() public {
        uint256 gasBefore = gasleft();
        verifier.mlDsaKeyGen(TEST_SEED);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("mlDsaKeyGen gas:", gasUsed);
    }

    function test_EcrecoverBaseline() public {
        bytes32 hash = keccak256(TEST_MSG);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, hash);
        uint256 gasBefore = gasleft();
        ecrecover(hash, v, r, s);
        uint256 gasUsed = gasBefore - gasleft();
        console.log("ecrecover (baseline) gas:", gasUsed);
    }
}
