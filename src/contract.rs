#[cfg(not(feature = "library"))]
use cosmwasm_std::{
    entry_point, from_binary, to_binary, BankMsg, Binary, Coin, CosmosMsg, Deps, DepsMut, Env,
    Event, MessageInfo, Response, StdError, StdResult, Timestamp, Uint128, Uint64,
};
use cw2::{get_contract_version, set_contract_version};
use cw20::{Cw20Contract, Cw20ExecuteMsg};
use cw_utils::{Expiration, Scheduled};
use semver::Version;
use sha2::Digest;
use std::convert::TryInto;

use crate::error::ContractError;
use crate::helpers::CosmosSignature;
use crate::msg::{
    ActiveDelayResponse, ActiveResponse, ClaimedResponse, ConfigResponse, DistResponse, ExecuteMsg,
    InstantiateMsg, IsPausedResponse, LatestStageResponse, MigrateMsg, QueryMsg, RoleResponse,
    SignatureInfo,
};
use crate::rbac::*;
use crate::state::*;

// Version info, for migration info
const CONTRACT_NAME: &str = "babylon:cosmos-merkle-airdrop";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
// Simple static role definitions
pub const DEFAULT_ADMIN_ROLE: &[u8] = b"default_admin";
pub const OPERATOR_ROLE: &[u8] = b"operator";
pub const PAUSE_ROLE: &[u8] = b"pause";
// Event tag for contract events
pub const EVENT_UPDATE_CONFIG: &str = "update_config";
pub const EVENT_REGISTER_ROOT: &str = "register_root";
pub const EVENT_CLAIM: &str = "claim";
pub const EVENT_PAUSE: &str = "pause";
pub const EVENT_UNPAUSE: &str = "unpause";
pub const EVENT_SET_DELAY: &str = "set_delay";
pub const EVENT_UPDATE_ROOT: &str = "update_root";
pub const EVENT_UPDATE_DURATION: &str = "update_duration";
pub const EVENT_SET_AIRDROP: &str = "set_airdrop";
pub const EVENT_GRANT_ROLE: &str = "grant_role";
pub const EVENT_REVOKE_ROLE: &str = "revoke_role";

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    let admin = msg
        .default_admin
        .map_or(Ok(info.sender), |o| deps.api.addr_validate(&o))?;

    grant_role(deps.storage, DEFAULT_ADMIN_ROLE, &admin)?;
    grant_role(deps.storage, OPERATOR_ROLE, &admin)?;
    grant_role(deps.storage, PAUSE_ROLE, &admin)?;
    let stage = 0;
    LATEST_STAGE.save(deps.storage, &stage)?;

    make_config(deps, &msg.cw20_token_address, &msg.native_token)?;

    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::UpdateConfig {
            new_cw20_address,
            new_native_token,
        } => execute_update_config(deps, env, info, new_cw20_address, new_native_token),
        ExecuteMsg::RegisterRoot {
            root,
            duration,
            hrp,
        } => execute_register_root(deps, env, info, root, duration, hrp),
        ExecuteMsg::Claim {
            amount,
            proof,
            sig_info,
        } => execute_claim(deps, env, info, amount, proof, sig_info),
        ExecuteMsg::Pause {} => execute_pause(deps, env, info),
        ExecuteMsg::UnPause {} => execute_unpause(deps, env, info),
        ExecuteMsg::SetDelay { delay } => execute_set_delay(deps, env, info, delay),
        ExecuteMsg::UpdateRoot { root } => execute_update_root(deps, env, info, root),
        ExecuteMsg::SetAirdrop { disable } => execute_set_airdrop(deps, env, info, disable),
        ExecuteMsg::UpdateDuration { duration } => {
            execute_update_duration(deps, env, info, duration)
        }
        ExecuteMsg::GrantRole { role, address } => {
            execute_grant_role(deps, env, info, role, address)
        }
        ExecuteMsg::RevokeRole { role, address } => {
            execute_revoke_role(deps, env, info, role, address)
        }
    }
}

pub fn make_config(
    deps: DepsMut,
    cw20_token_address: &Option<String>,
    native_token: &Option<String>,
) -> Result<Response, ContractError> {
    let config: Config = match (native_token, cw20_token_address) {
        (Some(native), None) => Ok(Config {
            cw20_token_address: None,
            native_token: Some(native.clone()),
        }),
        (None, Some(cw20_addr)) => Ok(Config {
            cw20_token_address: Some(deps.api.addr_validate(&cw20_addr)?),
            native_token: None,
        }),
        _ => Err(ContractError::InvalidTokenType {}),
    }?;
    CONFIG.save(deps.storage, &config)?;
    Ok(Response::default())
}

pub fn assert_not_paused(deps: &DepsMut) -> Result<(), ContractError> {
    let paused = PAUSED.load(deps.storage)?;
    if paused {
        return Err(ContractError::ContractPaused {});
    }
    Ok(())
}

fn is_active(deps: Deps, env: &Env, stage: u8) -> StdResult<bool> {
    if stage == 0 {
        return Ok(false);
    }
    let dist = DIST.load(deps.storage, stage)?;
    if dist.disable {
        return Ok(false);
    }
    let current_time = env.block.time.seconds();
    Ok(current_time <= dist.activate_at.u64() + dist.duration.u64())
}

// Check admin permission
pub fn assert_admin(deps: &DepsMut, info: &MessageInfo) -> Result<(), ContractError> {
    if !has_role(deps.storage, DEFAULT_ADMIN_ROLE, &info.sender)? {
        return Err(ContractError::Unauthorized {});
    }
    Ok(())
}

// Check operator permission
pub fn assert_operator(deps: &DepsMut, info: &MessageInfo) -> Result<(), ContractError> {
    if !has_role(deps.storage, OPERATOR_ROLE, &info.sender)? {
        return Err(ContractError::Unauthorized {});
    }
    Ok(())
}

// Check pause permission
pub fn assert_pauser(deps: &DepsMut, info: &MessageInfo) -> Result<(), ContractError> {
    if !has_role(deps.storage, PAUSE_ROLE, &info.sender)? {
        return Err(ContractError::Unauthorized {});
    }
    Ok(())
}

pub fn execute_update_config(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    cw20_token_address: Option<String>,
    native_token: Option<String>,
) -> Result<Response, ContractError> {
    // only operator
    if !has_role(deps.storage, OPERATOR_ROLE, &info.sender)? {
        return Err(ContractError::Unauthorized {});
    }

    make_config(deps, &cw20_token_address, &native_token)?;
    let update_config_event = Event::new(EVENT_UPDATE_CONFIG)
        .add_attribute("cw20_token_address", cw20_token_address.unwrap_or_default())
        .add_attribute("native_token", native_token.unwrap_or_default());
    Ok(Response::new().add_event(update_config_event))
}

#[allow(clippy::too_many_arguments)]
pub fn execute_register_root(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    root: String,
    duration: Uint64,
    hrp: Option<String>,
) -> Result<Response, ContractError> {
    // only operator
    if !has_role(deps.storage, OPERATOR_ROLE, &info.sender)? {
        return Err(ContractError::Unauthorized {});
    }

    let stage = LATEST_STAGE.load(deps.storage)?;

    // check if the current stage is active
    if is_active(deps.as_ref(), &env, stage)? {
        return Err(ContractError::StageNotExpired {
            stage,
            expiration: Expiration::Never {},
        });
    }

    // update the stage to the next one
    let new_stage = stage + 1;
    LATEST_STAGE.save(deps.storage, &new_stage)?;

    let active_delay = ACTIVATION_DELAY.may_load(deps.storage)?.unwrap_or(0);

    // save the new distribution info
    let dist = Dist {
        activate_at: Uint64::from(env.block.time.seconds() + active_delay),
        duration,
        root,
        disable: false,
        hrp: hrp,
    };
    DIST.save(deps.storage, new_stage, &dist)?;

    let register_root_event = Event::new(EVENT_REGISTER_ROOT)
        .add_attribute("stage", new_stage.to_string())
        .add_attribute("root", dist.root)
        .add_attribute("duration", duration.to_string())
        .add_attribute("activate_at", dist.activate_at.to_string())
        .add_attribute("hrp", dist.hrp.unwrap_or_default());
    Ok(Response::new().add_event(register_root_event))
}

pub fn execute_claim(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
    proof: Vec<String>,
    sig_info: Option<SignatureInfo>,
) -> Result<Response, ContractError> {
    // get current stage
    let stage = LATEST_STAGE.load(deps.storage)?;
    if stage == 0 {
        return Err(ContractError::InvalidInput {});
    }
    // get distribution info
    let dist = DIST.load(deps.storage, stage)?;

    // check if the current stage is active
    if dist.disable {
        return Err(ContractError::StagePaused { stage });
    }

    // check if the current time is within the distribution period
    let current_time = env.block.time.seconds();
    if current_time < dist.activate_at.u64() {
        return Err(ContractError::StageNotBegun {
            stage,
            start: Scheduled::AtTime(Timestamp::from_seconds(dist.activate_at.u64())),
        });
    }
    if current_time > dist.activate_at.u64() + dist.duration.u64() {
        return Err(ContractError::StageExpired {
            stage,
            expiration: Expiration::AtTime(Timestamp::from_seconds(
                dist.activate_at.u64() + dist.duration.u64(),
            )),
        });
    }

    let is_paused = PAUSED.may_load(deps.storage)?;
    if is_paused.unwrap_or(false) {
        return Err(ContractError::StagePaused { stage });
    }
    // if present verify signature and extract external address or use info.sender as proof
    // if signature is not present in the message, verification will fail since info.sender is not present in the merkle root
    let send_proof_addr = match sig_info {
        None => (info.sender.to_string(), info.sender.to_string()),
        Some(sig) => {
            // verify signature
            let cosmos_signature: CosmosSignature = from_binary(&sig.signature)?;
            if sig.hrp_flag {
                let hrp = dist.hrp.ok_or(ContractError::InvalidInput {})?;
                cosmos_signature.verify(deps.as_ref(), &sig.claim_msg)?;
                // get airdrop stage bech32 prefix and derive proof address from public key
                let proof_addr = cosmos_signature.derive_cosmos_addr_from_pubkey(hrp.as_str())?;
                let send_claim = sig.extract_addr()?;
                if send_claim.1 != info.sender.to_string() {
                    return Err(ContractError::VerificationFailed {});
                }
                (send_claim.0, proof_addr)
            } else {
                let recovery_id = sig.recovery_id.ok_or(ContractError::InvalidInput {})?;
                let proof_addr = cosmos_signature.derive_evm_addr_from_sig(
                    deps.as_ref(),
                    &sig.claim_msg,
                    recovery_id,
                )?;
                let send_claim = sig.extract_addr()?;
                if send_claim.1 != info.sender.to_string() {
                    return Err(ContractError::VerificationFailed {});
                }
                (send_claim.0, proof_addr)
            }
        }
    };
    // check if the user has already claimed
    let claimed = CLAIMED.may_load(deps.storage, (send_proof_addr.1.clone(), stage))?;
    if claimed.unwrap_or(false) {
        return Err(ContractError::Claimed {});
    }
    // verify merkle root
    let user_input = format!("{}{}", send_proof_addr.1.clone(), amount);
    let hash = sha2::Sha256::digest(user_input.as_bytes())
        .as_slice()
        .try_into()
        .map_err(|_| ContractError::WrongLength {})?;

    let hash = proof.into_iter().try_fold(hash, |hash, p| {
        let mut proof_buf = [0; 32];
        hex::decode_to_slice(p, &mut proof_buf)?;
        let mut hashes = [hash, proof_buf];
        hashes.sort_unstable();
        sha2::Sha256::digest(&hashes.concat())
            .as_slice()
            .try_into()
            .map_err(|_| ContractError::WrongLength {})
    })?;
    let mut root_buf: [u8; 32] = [0; 32];
    hex::decode_to_slice(dist.root, &mut root_buf)?;
    print!("calculate hash: 0x{}", hex::encode(hash));
    if root_buf != hash {
        return Err(ContractError::VerificationFailed {});
    }
    // Update claim index to the current stage
    CLAIMED.save(deps.storage, (send_proof_addr.1.clone(), stage), &true)?;

    let config = CONFIG.load(deps.storage)?;
    let message: CosmosMsg = match (config.cw20_token_address, config.native_token) {
        (Some(cw20_addr), None) => {
            let msg = Cw20ExecuteMsg::Transfer {
                recipient: send_proof_addr.0.clone(),
                amount,
            };
            Cw20Contract(cw20_addr)
                .call(msg)
                .map_err(ContractError::Std)
        }
        (None, Some(native)) => {
            let balance = deps
                .querier
                .query_balance(env.contract.address, native.clone())?;
            if balance.amount < amount {
                return Err(ContractError::InsufficientFunds {
                    balance: balance.amount,
                    amount,
                });
            }
            let msg = BankMsg::Send {
                to_address: send_proof_addr.0.clone(),
                amount: vec![Coin {
                    denom: native,
                    amount,
                }],
            };
            Ok(CosmosMsg::Bank(msg))
        }
        _ => Err(ContractError::InvalidTokenType {}),
    }?;
    let claim_event = Event::new(EVENT_CLAIM)
        .add_attribute("stage", stage.to_string())
        .add_attribute("address", send_proof_addr.0)
        .add_attribute("amount", amount);
    let res = Response::new().add_message(message).add_event(claim_event);
    Ok(res)
}

pub fn execute_pause(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    assert_pauser(&deps, &info)?;
    PAUSED.save(deps.storage, &true)?;
    let pause_event = Event::new(EVENT_PAUSE);
    Ok(Response::new().add_event(pause_event))
}

pub fn execute_unpause(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    assert_pauser(&deps, &info)?;
    PAUSED.save(deps.storage, &false)?;
    let unpause_event = Event::new(EVENT_UNPAUSE);
    Ok(Response::new().add_event(unpause_event))
}

pub fn execute_set_delay(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    delay: u64,
) -> Result<Response, ContractError> {
    assert_operator(&deps, &info)?;
    let pre_delay = ACTIVATION_DELAY.may_load(deps.storage)?;
    ACTIVATION_DELAY.save(deps.storage, &delay)?;
    let set_delay_event = Event::new(EVENT_SET_DELAY)
        .add_attribute("pre_value", pre_delay.unwrap_or(0).to_string())
        .add_attribute("new_value", delay.to_string());
    Ok(Response::new().add_event(set_delay_event))
}

pub fn execute_update_root(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    root: String,
) -> Result<Response, ContractError> {
    assert_operator(&deps, &info)?;
    let stage = LATEST_STAGE.load(deps.storage)?;
    if stage == 0 {
        return Err(ContractError::InvalidInput {});
    }
    let dist = DIST.load(deps.storage, stage)?;
    DIST.save(
        deps.storage,
        stage,
        &Dist {
            root: root.clone(),
            activate_at: dist.activate_at,
            duration: dist.duration,
            disable: dist.disable,
            hrp: dist.hrp,
        },
    )?;
    let update_root_event = Event::new(EVENT_UPDATE_ROOT)
        .add_attribute("stage", stage.to_string())
        .add_attribute("pre_root", dist.root)
        .add_attribute("new_root", root);
    Ok(Response::new().add_event(update_root_event))
}

pub fn execute_set_airdrop(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    disable: bool,
) -> Result<Response, ContractError> {
    assert_operator(&deps, &info)?;
    let stage = LATEST_STAGE.load(deps.storage)?;
    if stage == 0 {
        return Err(ContractError::InvalidInput {});
    }
    let dist = DIST.load(deps.storage, stage)?;
    DIST.save(
        deps.storage,
        stage,
        &Dist {
            root: dist.root,
            activate_at: dist.activate_at,
            duration: dist.duration,
            disable: disable,
            hrp: dist.hrp,
        },
    )?;
    let set_airdrop_event = Event::new(EVENT_SET_AIRDROP)
        .add_attribute("stage", stage.to_string())
        .add_attribute("disable", disable.to_string());
    Ok(Response::new().add_event(set_airdrop_event))
}

pub fn execute_update_duration(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    duration: u64,
) -> Result<Response, ContractError> {
    assert_operator(&deps, &info)?;
    let stage = LATEST_STAGE.load(deps.storage)?;
    if stage == 0 {
        return Err(ContractError::InvalidInput {});
    }
    let dist = DIST.load(deps.storage, stage)?;
    DIST.save(
        deps.storage,
        stage,
        &Dist {
            root: dist.root,
            activate_at: dist.activate_at,
            duration: Uint64::from(duration),
            disable: dist.disable,
            hrp: dist.hrp,
        },
    )?;
    let update_duration_event = Event::new(EVENT_UPDATE_DURATION)
        .add_attribute("stage", stage.to_string())
        .add_attribute("pre_duration", dist.duration.to_string())
        .add_attribute("new_duration", duration.to_string());
    Ok(Response::new().add_event(update_duration_event))
}

pub fn execute_grant_role(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    role: String,
    address: String,
) -> Result<Response, ContractError> {
    assert_admin(&deps, &info)?;
    let addr = deps.api.addr_validate(&address)?;
    grant_role(deps.storage, role.as_bytes(), &addr)?;
    let grant_role_event = Event::new(EVENT_GRANT_ROLE)
        .add_attribute("role", role)
        .add_attribute("address", addr);
    Ok(Response::new().add_event(grant_role_event))
}

pub fn execute_revoke_role(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    role: String,
    address: String,
) -> Result<Response, ContractError> {
    assert_admin(&deps, &info)?;
    let addr = deps.api.addr_validate(&address)?;
    revoke_role(deps.storage, role.as_bytes(), &addr)?;
    let revoke_role_event = Event::new(EVENT_REVOKE_ROLE)
        .add_attribute("role", role)
        .add_attribute("address", addr);
    Ok(Response::new().add_event(revoke_role_event))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?),
        QueryMsg::StageDist { stage } => to_binary(&query_root(deps, stage)?),
        QueryMsg::LatestStage {} => to_binary(&query_latest_stage(deps)?),
        QueryMsg::HasClaimed { stage, users } => to_binary(&query_claimed(deps, stage, users)?),
        QueryMsg::IsPaused {} => to_binary(&query_paused(deps)?),
        QueryMsg::IsActive {} => to_binary(&query_active(deps, env)?),
        QueryMsg::HasRole { role, address } => to_binary(&query_has_role(deps, role, address)?),
        QueryMsg::ActiveDelay {} => to_binary(&query_active_delay(deps)?),
    }
}

pub fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let cfg = CONFIG.load(deps.storage)?;
    Ok(ConfigResponse {
        cw20_token_address: cfg.cw20_token_address.map(|o| o.to_string()),
        native_token: cfg.native_token,
    })
}

pub fn query_root(deps: Deps, stage: u8) -> StdResult<DistResponse> {
    if stage == 0 {
        return Err(StdError::generic_err("Invalid stage"));
    }
    let dist = DIST.load(deps.storage, stage)?;

    let resp = DistResponse {
        stage,
        activate_at: dist.activate_at,
        duration: dist.duration,
        root: dist.root,
        disable: dist.disable,
        hrp: dist.hrp,
    };
    Ok(resp)
}

pub fn query_latest_stage(deps: Deps) -> StdResult<LatestStageResponse> {
    let latest_stage = LATEST_STAGE.load(deps.storage)?;
    let resp = LatestStageResponse { latest_stage };

    Ok(resp)
}

pub fn query_claimed(deps: Deps, stage: u8, users: Vec<String>) -> StdResult<ClaimedResponse> {
    let claimed = users
        .into_iter()
        .map(|user| {
            let claimed = CLAIMED.may_load(deps.storage, (user, stage))?;
            Ok(claimed.unwrap_or(false))
        })
        .collect::<StdResult<Vec<bool>>>()?;

    let resp = ClaimedResponse { claimed };
    Ok(resp)
}

pub fn query_paused(deps: Deps) -> StdResult<IsPausedResponse> {
    let is_paused = PAUSED.may_load(deps.storage)?;
    let resp = IsPausedResponse {
        is_paused: is_paused.unwrap_or(false),
    };
    Ok(resp)
}

pub fn query_active_delay(deps: Deps) -> StdResult<ActiveDelayResponse> {
    let active_delay = ACTIVATION_DELAY.may_load(deps.storage)?;
    let resp = ActiveDelayResponse {
        active_delay: active_delay.unwrap_or(0),
    };
    Ok(resp)
}
pub fn query_active(deps: Deps, env: Env) -> StdResult<ActiveResponse> {
    let stage = LATEST_STAGE.load(deps.storage)?;
    let is_active = is_active(deps, &env, stage)?;
    let resp = ActiveResponse { is_active };
    Ok(resp)
}

pub fn query_has_role(deps: Deps, role: String, address: String) -> StdResult<RoleResponse> {
    let addr = deps.api.addr_validate(&address)?;
    let has_role = has_role(deps.storage, role.as_bytes(), &addr)?;
    let resp = RoleResponse { has_role };
    Ok(resp)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    let contract_info = get_contract_version(deps.storage)?;
    if contract_info.contract != CONTRACT_NAME {
        return Err(ContractError::CannotMigrate {
            previous_contract: contract_info.contract,
        });
    }
    let contract_version: Version = contract_info.version.parse()?;
    let current_version: Version = CONTRACT_VERSION.parse()?;
    if contract_version < current_version {
        set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
        Ok(Response::default())
    } else {
        Err(ContractError::CannotMigrate {
            previous_contract: contract_info.version,
        })
    }
}
