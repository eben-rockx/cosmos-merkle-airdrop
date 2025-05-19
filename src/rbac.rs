use cosmwasm_std::{Addr, StdResult, Storage};
use cw_storage_plus::Map;

// Role member table, key is (role_bytes, user_address)
pub const ROLE_MEMBERS: Map<(&[u8], &Addr), bool> = Map::new("role_members");

pub fn has_role(storage: &dyn Storage, role: &[u8], addr: &Addr) -> StdResult<bool> {
    Ok(ROLE_MEMBERS
        .may_load(storage, (role, addr))?
        .unwrap_or(false))
}

pub fn grant_role(storage: &mut dyn Storage, role: &[u8], addr: &Addr) -> StdResult<()> {
    if has_role(storage, role, addr)? {
        return Ok(());
    }
    ROLE_MEMBERS.save(storage, (role, addr), &true)
}

pub fn revoke_role(storage: &mut dyn Storage, role: &[u8], addr: &Addr) -> StdResult<()> {
    if !has_role(storage, role, addr)? {
        return Ok(());
    }
    ROLE_MEMBERS.save(storage, (role, addr), &false)
}
