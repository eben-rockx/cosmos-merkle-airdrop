use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint64};
use cw_storage_plus::{Item, Map};

#[cw_serde]
pub struct Config {
    pub cw20_token_address: Option<Addr>,
    pub native_token: Option<String>,
}

#[cw_serde]
pub struct Dist {
    pub activate_at: Uint64,
    pub duration: Uint64,
    pub root: String,
    pub disable: bool,
    pub hrp: Option<String>,
}

pub const CONFIG_KEY: &str = "config";
pub const CONFIG: Item<Config> = Item::new(CONFIG_KEY);

pub const LATEST_STAGE_KEY: &str = "stage";
pub const LATEST_STAGE: Item<u8> = Item::new(LATEST_STAGE_KEY);

pub const DIST_KEY: &str = "dist";
pub const DIST: Map<u8, Dist> = Map::new(DIST_KEY);

pub const CLAIMED_KEY: &str = "claimed";
pub const CLAIMED: Map<(String, u8), bool> = Map::new(CLAIMED_KEY);

pub const ACTIVATION_DELAY_KEY: &str = "activation_delay";
pub const ACTIVATION_DELAY: Item<u64> = Item::new(ACTIVATION_DELAY_KEY);

pub const PAUSED_KEY: &str = "paused";
pub const PAUSED: Item<bool> = Item::new(PAUSED_KEY);
