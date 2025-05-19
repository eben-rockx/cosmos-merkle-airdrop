use crate::ContractError;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{from_slice, Binary, Uint128, Uint64};
use serde::{Deserialize, Serialize};

#[cw_serde]
pub struct InstantiateMsg {
    /// Owner if none set to info.sender.
    pub default_admin: Option<String>,
    pub cw20_token_address: Option<String>,
    pub native_token: Option<String>,
}

#[cw_serde]
pub enum ExecuteMsg {
    UpdateConfig {
        new_cw20_address: Option<String>,
        new_native_token: Option<String>,
    },
    RegisterRoot {
        /// MerkleRoot is hex-encoded merkle root.
        root: String,
        duration: Uint64,
        // hrp is the bech32 parameter required for building external network address
        // from signature message during claim action. example "cosmos", "terra", "juno"
        hrp: Option<String>,
    },
    /// Claim does not check if contract has enough funds, owner must ensure it.
    Claim {
        amount: Uint128,
        /// Proof is hex-encoded merkle proof.
        proof: Vec<String>,
        /// Enables cross chain airdrops.
        /// Target wallet proves identity by sending a signed [SignedClaimMsg](SignedClaimMsg)
        /// containing the recipient address.
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

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(ConfigResponse)]
    Config {},
    #[returns(DistResponse)]
    StageDist { stage: u8 },
    #[returns(LatestStageResponse)]
    LatestStage {},
    #[returns(ClaimedResponse)]
    HasClaimed { stage: u8, users: Vec<String> },
    #[returns(IsPausedResponse)]
    IsPaused {},
    #[returns(ActiveResponse)]
    IsActive {},
    #[returns(RoleResponse)]
    HasRole { role: String, address: String },
    #[returns(ActiveDelayResponse)]
    ActiveDelay {},
}

#[cw_serde]
pub struct ConfigResponse {
    pub cw20_token_address: Option<String>,
    pub native_token: Option<String>,
}

#[cw_serde]
pub struct DistResponse {
    pub stage: u8,
    /// Dist info.
    pub activate_at: Uint64,
    pub duration: Uint64,
    pub root: String,
    pub disable: bool,
    pub hrp: Option<String>,
}

#[cw_serde]
pub struct LatestStageResponse {
    pub latest_stage: u8,
}

#[cw_serde]
pub struct ClaimedResponse {
    pub claimed: Vec<bool>,
}

#[cw_serde]
pub struct IsPausedResponse {
    pub is_paused: bool,
}

#[cw_serde]
pub struct ActiveResponse {
    pub is_active: bool,
}

#[cw_serde]
pub struct RoleResponse {
    pub has_role: bool,
}

#[cw_serde]
pub struct ActiveDelayResponse {
    pub active_delay: u64,
}

#[cw_serde]
pub struct MigrateMsg {}

// Signature verification is done on external airdrop claims.
#[cw_serde]
pub struct SignatureInfo {
    pub claim_msg: Binary,
    pub signature: Binary,
    pub hrp_flag: bool,
    pub recovery_id: Option<u8>,
}
impl SignatureInfo {
    pub fn extract_addr(&self) -> Result<(String, String), ContractError> {
        let claim_msg = from_slice::<ClaimMsg>(&self.claim_msg)?;
        Ok((claim_msg.send_address, claim_msg.claim_address))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ClaimMsg {
    #[serde(rename = "send")]
    send_address: String,
    #[serde(rename = "claim")]
    claim_address: String,
}
