# CW20 Merkle Airdrop

This is a merkle airdrop smart contract that works with cw20 token specification Mass airdrop distributions made cheap
and efficient.

Explanation of merkle
airdrop: [Medium Merkle Airdrop: the Basics](https://medium.com/smartz-blog/merkle-airdrop-the-basics-9a0857fcc930)

Traditional and non-efficient airdrops:

- Distributor creates a list of airdrop
- Sends bank send messages to send tokens to recipients

**Or**

- Stores list of recipients on smart contract data
- Recipient claims the airdrop

These two solutions are very ineffective when recipient list is big. First, costly because bank send cost for the
distributor will be costly. Second, whole airdrop list stored in the state, again costly.

Merkle Airdrop is very efficient even when recipient number is massive.

This contract works with multiple airdrop rounds, meaning you can execute several airdrops using same instance.

Uses **SHA256** for merkle root tree construction.

## Procedure

- Distributor of contract prepares a list of addresses with many entries and publishes this list in public static .js
  file in JSON format
- Distributor reads this list, builds the merkle tree structure and writes down the Merkle root of it.
- Distributor creates contract and places calculated Merkle root into it.
- Distributor says to users, that they can claim their tokens, if they owe any of addresses, presented in list,
  published on distributor's site.
- User wants to claim his N tokens, he also builds Merkle tree from public list and prepares Merkle proof, consisting
  from log2N hashes, describing the way to reach Merkle root
- User sends transaction with Merkle proof to contract
- Contract checks Merkle proof, and, if proof is correct, then sender's address is in list of allowed addresses, and
  contract does some action for this use.
- Distributor sends token to the contract, and registers new merkle root for the next distribution round.

## Spec

### Messages

#### InstantiateMsg

`InstantiateMsg` instantiates contract with owner and cw20 token address. Airdrop `stage` is set to 0.

```rust
pub struct InstantiateMsg {
    /// Owner if none set to info.sender.
    pub default_admin: Option<String>,
    pub cw20_token_address: Option<String>,
    pub native_token: Option<String>,
}
```

#### ExecuteMsg

```rust
pub enum ExecuteMsg {
    UpdateConfig {
        new_cw20_address: Option<String>,
        new_native_token: Option<String>,
    },
    RegisterRoot {
        root: String,
        duration: Uint64,
        hrp: Option<String>,
    },
    Claim {
        amount: Uint128,
        proof: Vec<String>,
        sig_info: Option<SignatureInfo>,
    },
    Pause {},
    UnPause {},
    SetDelay {
        delay: u64,
    },
    UpdateRoot {
        root: String,
    },
    UpdateDuration {
        duration: u64,
    },
    SetAirdrop {
        disable: bool,
    },
    GrantRole {
        role: String,
        address: String,
    },
    RevokeRole {
        role: String,
        address: String,
    },
}
```

- `UpdateConfig{}` updates configuration.
- `RegisterMerkleRoot {merkle_root}` registers merkle tree root for further claim verification. Airdrop `Stage`
  increased by 1.
- `Claim{amount, proof}` recipient executes for claiming airdrop with, `amount` and `proof` data built
  using full list.

#### QueryMsg

``` rust
pub enum QueryMsg {
    Config {},
    StageDist { stage: u8 },
    LatestStage {},
    HasClaimed { stage: u8, users: Vec<String> },
    IsPaused {},
    IsActive {},
    HasRole { role: String, address: String },
    ActiveDelay {},
}
```

- `{ config: {} }` returns configuration, `{"cw20_token_address": ..., "native_token": ...}`.
- `{ stage_dist: { stage: 1 }` returns merkle root of given stage, `{"root": ... , "stage": ...}`
- `{ latest_stage: {}}` returns current airdrop stage, `{"latest_stage": ...}`
- `{ has_claimed: {stage: 1, users: ["wasm1..."]}` returns if address claimed airdrop, `{["true"]}`

## Merkle Airdrop CLI

[Merkle Airdrop CLI](helpers) contains js helpers for generating root, generating and verifying proofs for given airdrop
file.

## Test Vector Generation

Test vector can be generated using commands at [Merkle Airdrop CLI README](helpers/README.md)

## Build
`RUSTFLAGS="-C link-arg=-s" cargo build --release --target=wasm32-unknown-unknown --locked`

`wasm-opt -Oz -o optimized-airdrop.wasm target/wasm32-unknown-unknown/release/cw20_merkle_airdrop.wasm`