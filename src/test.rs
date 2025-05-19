#[cfg(test)]
mod tests {
    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::testing::{
        mock_dependencies, mock_dependencies_with_balance, mock_env, mock_info,
    };
    use cosmwasm_std::{
        from_binary, to_binary, from_slice, Addr, BankMsg, Binary, Coin, CosmosMsg, WasmMsg, SubMsg, Env, Event,
        MessageInfo, Response, StdError, StdResult, Timestamp, Uint128, Uint64, Empty,
    };
    use cw20::MinterResponse;
    use cw_multi_test::{App, Contract, ContractWrapper, Executor};
    use cw_utils::Expiration::AtHeight;
    use serde::{Deserialize, Serialize};

    use crate::contract::*;
    use crate::error::ContractError;
    use crate::msg::{
        ActiveDelayResponse, ActiveResponse, ClaimedResponse, ConfigResponse, DistResponse,
        ExecuteMsg, InstantiateMsg, IsPausedResponse, LatestStageResponse, MigrateMsg, QueryMsg,
        RoleResponse, SignatureInfo,
    };
    use crate::rbac::*;
    use crate::state::*;
    use cw20::{Cw20Contract, Cw20ExecuteMsg};
    use cw_utils::{Expiration, Scheduled};
    use crate::helpers::CosmosSignature;

    fn mock_app() -> App {
        App::default()
    }

    pub fn contract_cw20_merkle_airdrop() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(execute, instantiate, query);
        Box::new(contract)
    }

    pub fn contract_cw20() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(
            cw20_base::contract::execute,
            cw20_base::contract::instantiate,
            cw20_base::contract::query,
        );
        Box::new(contract)
    }

    #[test]
    fn proper_instantiation_cw20() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            default_admin: Some("owner0000".to_string()),
            cw20_token_address: Some("anchor0000".to_string()),
            native_token: None,
        };

        let env = mock_env();
        let info = mock_info("addr0000", &[]);

        // we can just call .unwrap() to assert this was a success
        let _res = instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();

        // it worked, let's query the state
        let res = query(deps.as_ref(), env.clone(), QueryMsg::Config {}).unwrap();
        let config: ConfigResponse = from_binary(&res).unwrap();
        assert_eq!(
            true,
            has_role(
                &deps.storage,
                DEFAULT_ADMIN_ROLE,
                &Addr::unchecked("owner0000")
            )
            .is_ok()
        );
        assert_eq!("anchor0000", config.cw20_token_address.unwrap().as_str());
        assert_eq!(None, config.native_token);

        let res = query(deps.as_ref(), env, QueryMsg::LatestStage {}).unwrap();
        let latest_stage: LatestStageResponse = from_binary(&res).unwrap();
        assert_eq!(0u8, latest_stage.latest_stage);
    }

    #[test]
    fn proper_instantiation_native() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            default_admin: Some("owner0000".to_string()),
            cw20_token_address: None,
            native_token: Some(String::from("ujunox")),
        };

        let env = mock_env();
        let info = mock_info("addr0000", &[]);

        // we can just call .unwrap() to assert this was a success
        let _res = instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();

        // it worked, let's query the state
        let res = query(deps.as_ref(), env.clone(), QueryMsg::Config {}).unwrap();
        let config: ConfigResponse = from_binary(&res).unwrap();
        assert_eq!(
            true,
            has_role(
                &deps.storage,
                DEFAULT_ADMIN_ROLE,
                &Addr::unchecked("owner0000")
            )
            .is_ok()
        );
        assert_eq!("ujunox", config.native_token.unwrap().as_str());
        assert_eq!(None, config.cw20_token_address);

        let res = query(deps.as_ref(), env, QueryMsg::LatestStage {}).unwrap();
        let latest_stage: LatestStageResponse = from_binary(&res).unwrap();
        assert_eq!(0u8, latest_stage.latest_stage);
    }

    #[test]
    fn failed_instantiation_native_and_cw20() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            default_admin: Some("owner0000".to_string()),
            cw20_token_address: Some("anchor0000".to_string()),
            native_token: Some(String::from("ujunox")),
        };

        let env = mock_env();
        let info = mock_info("addr0000", &[]);

        assert_eq!(
            Err(ContractError::InvalidTokenType {}),
            instantiate(deps.as_mut(), env, info, msg)
        );
    }

    #[test]
    fn update_config() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            default_admin: None,
            cw20_token_address: Some("anchor0000".to_string()),
            native_token: None,
        };

        let env = mock_env();
        let info = mock_info("owner0000", &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        // update owner
        let env = mock_env();
        let info = mock_info("owner0000", &[]);
        let msg = ExecuteMsg::UpdateConfig {
            new_cw20_address: Some("cw20_0000".to_string()),
            new_native_token: None,
        };

        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(deps.as_ref(), env, QueryMsg::Config {}).unwrap();
        let config: ConfigResponse = from_binary(&res).unwrap();
        assert_eq!("cw20_0000", config.cw20_token_address.unwrap().as_str());

        // Unauthorized err
        let env = mock_env();
        let info = mock_info("owner0001", &[]);
        let msg = ExecuteMsg::UpdateConfig {
            new_cw20_address: Some("cw20_0001".to_string()),
            new_native_token: None,
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(res, ContractError::Unauthorized {});

        //update with native token
        let env = mock_env();
        let info = mock_info("owner0000", &[]);
        let msg = ExecuteMsg::UpdateConfig {
            new_cw20_address: None,
            new_native_token: Some("ujunox".to_string()),
        };

        let _res = execute(deps.as_mut(), env.clone(), info, msg).ok();

        let query_result = query(deps.as_ref(), env, QueryMsg::Config {}).unwrap();
        let config: ConfigResponse = from_binary(&query_result).unwrap();
        assert_eq!("ujunox", config.native_token.unwrap().as_str());

        //update cw20_address and native token together
        let env = mock_env();
        let info = mock_info("owner0000", &[]);
        let msg = ExecuteMsg::UpdateConfig {
            new_cw20_address: Some("cw20_0001".to_string()),
            new_native_token: Some("ujunox".to_string()),
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(res, ContractError::InvalidTokenType {});
    }

    #[test]
    fn register_merkle_root() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            default_admin: Some("owner0000".to_string()),
            cw20_token_address: Some("anchor0000".to_string()),
            native_token: None,
        };

        let env = mock_env();
        let info = mock_info("addr0000", &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        // register new merkle root
        let env = mock_env();
        let info = mock_info("owner0000", &[]);
        let msg = ExecuteMsg::RegisterRoot {
            root: "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37".to_string(),
            duration: Uint64::new(86400),
            hrp: None,
        };

        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        assert_eq!(
            res.events,
            vec![Event::new(EVENT_REGISTER_ROOT)
                .add_attribute("stage", "1")
                .add_attribute(
                    "root",
                    "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37"
                )
                .add_attribute("duration", "86400")
                .add_attribute("activate_at", "1571797419")
                .add_attribute("hrp", "")]
        );
        let res = query(deps.as_ref(), env.clone(), QueryMsg::LatestStage {}).unwrap();
        let latest_stage: LatestStageResponse = from_binary(&res).unwrap();
        assert_eq!(1u8, latest_stage.latest_stage);

        let res = query(
            deps.as_ref(),
            env,
            QueryMsg::StageDist {
                stage: latest_stage.latest_stage,
            },
        )
        .unwrap();
        let dist: DistResponse = from_binary(&res).unwrap();
        assert_eq!(
            "634de21cde1044f41d90373733b0f0fb1c1c71f9652b905cdf159e73c4cf0d37".to_string(),
            dist.root
        );
    }

    const TEST_DATA_1: &[u8] = include_bytes!("../testdata/airdrop_stage_1_test_data.json");
    const TEST_DATA_2: &[u8] = include_bytes!("../testdata/airdrop_stage_2_test_data.json");

    #[cw_serde]
    struct Encoded {
        account: String,
        amount: Uint128,
        root: String,
        proofs: Vec<String>,
        signed_msg: Option<SignatureInfo>,
        hrp: Option<String>,
    }

    #[test]
    fn claim_cw20() {
        // Run test 1
        let mut deps = mock_dependencies();
        let test_data: Encoded = from_slice(TEST_DATA_1).unwrap();

        let msg = InstantiateMsg {
            default_admin: Some("owner0000".to_string()),
            cw20_token_address: Some("token0000".to_string()),
            native_token: None,
        };

        let env = mock_env();
        let info = mock_info("addr0000", &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        let env = mock_env();
        let info = mock_info("owner0000", &[]);
        let msg = ExecuteMsg::RegisterRoot {
            root: test_data.root,
            duration: Uint64::new(86400),
            hrp: None,
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        let msg = ExecuteMsg::Claim {
            amount: test_data.amount,
            proof: test_data.proofs,
            sig_info: None,
        };

        let env = mock_env();
        let info = mock_info(test_data.account.as_str(), &[]);
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
        let expected = SubMsg::new(CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: "token0000".to_string(),
            funds: vec![],
            msg: to_binary(&Cw20ExecuteMsg::Transfer {
                recipient: test_data.account.clone(),
                amount: test_data.amount,
            })
            .unwrap(),
        }));
        assert_eq!(res.messages, vec![expected]);

        assert_eq!(
            res.events,
            vec![Event::new(EVENT_CLAIM)
                .add_attribute("stage", "1")
                .add_attribute("address", test_data.account.clone())
                .add_attribute("amount", test_data.amount)]
        );
        // Check address is claimed
        assert!(
            from_binary::<ClaimedResponse>(
                &query(
                    deps.as_ref(),
                    env.clone(),
                    QueryMsg::HasClaimed {
                        stage: 1,
                        users: vec![test_data.account],
                    },
                )
                .unwrap()
            )
            .unwrap()
            .claimed[0]
        );

        // check error on double claim
        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(res, ContractError::Claimed {});

        // Second test
        let test_data: Encoded = from_slice(TEST_DATA_2).unwrap();

        // register new drop
        let mut env = mock_env();
        env.block.time = env.block.time.plus_seconds(86405);
        let info = mock_info("owner0000", &[]);
        let msg = ExecuteMsg::RegisterRoot {
            root: test_data.root,
            duration: Uint64::new(86400),
            hrp: None,
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();
        // Claim next airdrop
        let msg = ExecuteMsg::Claim {
            amount: test_data.amount,
            proof: test_data.proofs,
            sig_info: None,
        };

        let mut env = mock_env();
        let info = mock_info(test_data.account.as_str(), &[]);
        env.block.time = env.block.time.plus_seconds(87400);
        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        let expected: SubMsg<_> = SubMsg::new(CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: "token0000".to_string(),
            funds: vec![],
            msg: to_binary(&Cw20ExecuteMsg::Transfer {
                recipient: test_data.account.clone(),
                amount: test_data.amount,
            })
            .unwrap(),
        }));
        assert_eq!(res.messages, vec![expected]);

        assert_eq!(
            res.events,
            vec![Event::new(EVENT_CLAIM)
                .add_attribute("stage", "2")
                .add_attribute("address", test_data.account.clone())
                .add_attribute("amount", test_data.amount)]
        );
    }

    #[test]
    fn claim_native() {
        // Run test 1
        let mut deps = mock_dependencies_with_balance(&[Coin {
            denom: "ujunox".to_string(),
            amount: Uint128::new(1234567),
        }]);
        let test_data: Encoded = from_slice(TEST_DATA_1).unwrap();

        let msg = InstantiateMsg {
            default_admin: Some("owner0000".to_string()),
            cw20_token_address: None,
            native_token: Some("ujunox".to_string()),
        };

        let env = mock_env();
        let info = mock_info("addr0000", &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        let env = mock_env();
        let info = mock_info("owner0000", &[]);
        let msg = ExecuteMsg::RegisterRoot {
            root: test_data.root,
            duration: Uint64::new(86400),
            hrp: None,
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        let msg = ExecuteMsg::Claim {
            amount: test_data.amount,
            proof: test_data.proofs,
            sig_info: None,
        };

        let env = mock_env();
        let info = mock_info(test_data.account.as_str(), &[]);
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
        let expected = SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
            to_address: test_data.account.clone(),
            amount: vec![Coin {
                denom: "ujunox".to_string(),
                amount: test_data.amount,
            }],
        }));
        assert_eq!(res.messages, vec![expected]);

        assert_eq!(
            res.events,
            vec![Event::new(EVENT_CLAIM)
                .add_attribute("stage", "1")
                .add_attribute("address", test_data.account.clone())
                .add_attribute("amount", test_data.amount)]
        );

        // Check address is claimed
        assert!(
            from_binary::<ClaimedResponse>(
                &query(
                    deps.as_ref(),
                    env.clone(),
                    QueryMsg::HasClaimed {
                        stage: 1,
                        users: vec![test_data.account],
                    },
                )
                .unwrap()
            )
            .unwrap()
            .claimed[0]
        );

        // check error on double claim
        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(res, ContractError::Claimed {});

        // Second test
        let test_data: Encoded = from_slice(TEST_DATA_2).unwrap();

        // register new drop
        let mut env = mock_env();
        env.block.time = env.block.time.plus_seconds(86405);
        let info = mock_info("owner0000", &[]);
        let msg = ExecuteMsg::RegisterRoot {
            root: test_data.root,
            duration: Uint64::new(86400),
            hrp: None,
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        // Claim next airdrop
        let msg = ExecuteMsg::Claim {
            amount: test_data.amount,
            proof: test_data.proofs,
            sig_info: None,
        };

        let mut env = mock_env();
        env.block.time = env.block.time.plus_seconds(87400);
        let info = mock_info(test_data.account.as_str(), &[]);
        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();
        let expected = SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
            to_address: test_data.account.clone(),
            amount: vec![Coin {
                denom: "ujunox".to_string(),
                amount: test_data.amount,
            }],
        }));
        assert_eq!(res.messages, vec![expected]);

        assert_eq!(
            res.events,
            vec![Event::new(EVENT_CLAIM)
                .add_attribute("stage", "2")
                .add_attribute("address", test_data.account)
                .add_attribute("amount", test_data.amount)]
        );
    }

    #[test]
    fn claim_native_insufficient_funds() {
        // Run test 1
        let mut deps = mock_dependencies_with_balance(&[Coin {
            denom: "ujunox".to_string(),
            amount: Uint128::zero(),
        }]);
        let test_data: Encoded = from_slice(TEST_DATA_1).unwrap();

        let msg = InstantiateMsg {
            default_admin: Some("owner0000".to_string()),
            cw20_token_address: None,
            native_token: Some("ujunox".to_string()),
        };

        let env = mock_env();
        let info = mock_info("addr0000", &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        let env = mock_env();
        let info = mock_info("owner0000", &[]);
        let msg = ExecuteMsg::RegisterRoot {
            root: test_data.root,
            duration: Uint64::new(86400),
            hrp: None,
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        let msg = ExecuteMsg::Claim {
            amount: test_data.amount,
            proof: test_data.proofs,
            sig_info: None,
        };

        let env = mock_env();
        let info = mock_info(test_data.account.as_str(), &[]);
        let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
        assert_eq!(
            ContractError::InsufficientFunds {
                balance: Uint128::zero(),
                amount: test_data.amount
            },
            res
        );
    }

    const TEST_DATA_1_MULTI: &[u8] =
        include_bytes!("../testdata/airdrop_stage_1_test_multi_data.json");

    #[cw_serde]
    struct Proof {
        account: String,
        amount: Uint128,
        proofs: Vec<String>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    struct MultipleData {
        total_claimed_amount: Uint128,
        root: String,
        accounts: Vec<Proof>,
    }

    #[test]
    fn multiple_claim_cw20() {
        // Run test 1
        let mut deps = mock_dependencies();
        let test_data: MultipleData = from_slice(TEST_DATA_1_MULTI).unwrap();

        let msg = InstantiateMsg {
            default_admin: Some("owner0000".to_string()),
            cw20_token_address: Some("token0000".to_string()),
            native_token: None,
        };

        let env = mock_env();
        let info = mock_info("addr0000", &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        let env = mock_env();
        let info = mock_info("owner0000", &[]);
        let msg = ExecuteMsg::RegisterRoot {
            root: test_data.root,
            duration: Uint64::new(86400),
            hrp: None,
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        // Loop accounts and claim
        for account in test_data.accounts.iter() {
            let msg = ExecuteMsg::Claim {
                amount: account.amount,
                proof: account.proofs.clone(),
                sig_info: None,
            };

            let env = mock_env();
            let info = mock_info(account.account.as_str(), &[]);
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
            let expected = SubMsg::new(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: "token0000".to_string(),
                funds: vec![],
                msg: to_binary(&Cw20ExecuteMsg::Transfer {
                    recipient: account.account.clone(),
                    amount: account.amount,
                })
                .unwrap(),
            }));
            assert_eq!(res.messages, vec![expected]);

            assert_eq!(
                res.events,
                vec![Event::new(EVENT_CLAIM)
                    .add_attribute("stage", "1")
                    .add_attribute("address", account.account.clone())
                    .add_attribute("amount", account.amount)]
            );
        }
    }

    #[test]
    fn multiple_claim_native() {
        // Run test 1
        let mut deps = mock_dependencies_with_balance(&[Coin {
            denom: "ujunox".to_string(),
            amount: Uint128::new(1234567),
        }]);
        let test_data: MultipleData = from_slice::<MultipleData>(TEST_DATA_1_MULTI).unwrap();

        let msg = InstantiateMsg {
            default_admin: Some("owner0000".to_string()),
            cw20_token_address: None,
            native_token: Some("ujunox".to_string()),
        };

        let env = mock_env();
        let info = mock_info("addr0000", &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        let env = mock_env();
        let info = mock_info("owner0000", &[]);
        let msg = ExecuteMsg::RegisterRoot {
            root: test_data.root,
            duration: Uint64::new(86400),
            hrp: None,
        };
        let _res = execute(deps.as_mut(), env, info, msg).unwrap();

        // Loop accounts and claim
        for account in test_data.accounts.iter() {
            let msg = ExecuteMsg::Claim {
                amount: account.amount,
                proof: account.proofs.clone(),
                sig_info: None,
            };

            let env = mock_env();
            let info = mock_info(account.account.as_str(), &[]);
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
            let expected = SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
                to_address: account.account.clone(),
                amount: vec![Coin {
                    denom: "ujunox".to_string(),
                    amount: account.amount,
                }],
            }));
            assert_eq!(res.messages, vec![expected]);

            assert_eq!(
                res.events,
                vec![Event::new(EVENT_CLAIM)
                    .add_attribute("stage", "1")
                    .add_attribute("address", account.account.clone())
                    .add_attribute("amount", account.amount)]
            );
        }
    }

    // Check expiration. Chain height in tests is 12345
    #[test]
    fn stage_expires() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            default_admin: Some("owner0000".to_string()),
            cw20_token_address: Some("token0000".to_string()),
            native_token: None,
        };

        let env = mock_env();
        let info = mock_info("addr0000", &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        // can register merkle root
        let mut env = mock_env();
        let info = mock_info("owner0000", &[]);
        let msg = ExecuteMsg::RegisterRoot {
            root: "5d4f48f147cb6cb742b376dce5626b2a036f69faec10cd73631c791780e150fc".to_string(),
            duration: Uint64::new(86400),
            hrp: None,
        };
        execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // can't claim expired
        let msg = ExecuteMsg::Claim {
            amount: Uint128::new(5),
            proof: vec![],
            sig_info: None,
        };

        let exp = 87400;
        let delta = exp - 86400;
        env.block.time = env.block.time.plus_seconds(exp);
        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap_err();
        assert_eq!(
            res,
            ContractError::StageExpired {
                stage: 1,
                expiration: Expiration::AtTime(Timestamp::from_seconds(
                    env.block.time.seconds() - delta
                )),
            }
        )
    }

    #[test]
    fn stage_starts() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg {
            default_admin: Some("owner0000".to_string()),
            cw20_token_address: Some("token0000".to_string()),
            native_token: None,
        };

        let env = mock_env();
        let info = mock_info("addr0000", &[]);
        let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        let env = mock_env();
        let info = mock_info("owner0000", &[]);
        let msg = ExecuteMsg::SetDelay { delay: 3600 };
        execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // can register merkle root
        let env = mock_env();
        let info = mock_info("owner0000", &[]);
        let msg = ExecuteMsg::RegisterRoot {
            root: "5d4f48f147cb6cb742b376dce5626b2a036f69faec10cd73631c791780e150fc".to_string(),
            duration: Uint64::new(86400),
            hrp: None,
        };
        execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // can't claim stage has not started yet
        let msg = ExecuteMsg::Claim {
            amount: Uint128::new(5),
            proof: vec![],
            sig_info: None,
        };

        let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap_err();
        assert_eq!(
            res,
            ContractError::StageNotBegun {
                stage: 1,
                start: Scheduled::AtTime(Timestamp::from_seconds(env.block.time.seconds() + 3600)),
            }
        )
    }

    mod external_sig {
        use super::*;
        use crate::msg::SignatureInfo;

        const TEST_DATA_EXTERNAL_SIG: &[u8] =
            include_bytes!("../testdata/airdrop_external_sig_test_data.json");
        #[test]
        fn test_cosmos_sig_verify_evm() {
            let deps = mock_dependencies();
            let signature_raw = Binary::from_base64("eyJwdWJfa2V5IjoiQTdDOTBNVTI4MzRnUEZhNk9ZMVR6V3ZQU25WcXJZUThpWTVCaVZ0d1RIbE8iLCJzaWduYXR1cmUiOiJzdmE0NU9WOWd2aERKYWJjK21HM3ZUVVdVT0xML21NbHFibWkwdDQrNi8xamNoZkgvRC9NcHNsS0lTK1RXTUN5YkY5WGg1RWRwWTZSZVBBSjl5djlYZz09In0=");

            let sig = SignatureInfo {
                hrp_flag: false,
                claim_msg: Binary::from_base64("eyJzZW5kIjoid2FzbTFxNGx5NXJtNmpwZmhoeDczeHZsbHBjNnVjbXIzeHJyNTBkdjVrcyIsImNsYWltIjoid2FzbTFxNGx5NXJtNmpwZmhoeDczeHZsbHBjNnVjbXIzeHJyNTBkdjVrcyJ9").unwrap(),
                signature: signature_raw.unwrap(),
                recovery_id: Some(1),
            };
            let cosmos_signature: CosmosSignature = from_binary(&sig.signature).unwrap();
            let res = cosmos_signature
                .verify(deps.as_ref(), &sig.claim_msg)
                .unwrap();
            assert!(res);
        }

        #[test]
        fn test_cosmos_eth_recover() {
            let deps = mock_dependencies();
            let signature_raw = Binary::from_base64("eyJwdWJfa2V5IjoiQTdDOTBNVTI4MzRnUEZhNk9ZMVR6V3ZQU25WcXJZUThpWTVCaVZ0d1RIbE8iLCJzaWduYXR1cmUiOiJzdmE0NU9WOWd2aERKYWJjK21HM3ZUVVdVT0xML21NbHFibWkwdDQrNi8xamNoZkgvRC9NcHNsS0lTK1RXTUN5YkY5WGg1RWRwWTZSZVBBSjl5djlYZz09In0=");

            let sig = SignatureInfo {
                hrp_flag: false,
                claim_msg: Binary::from_base64("eyJzZW5kIjoid2FzbTFxNGx5NXJtNmpwZmhoeDczeHZsbHBjNnVjbXIzeHJyNTBkdjVrcyIsImNsYWltIjoid2FzbTFxNGx5NXJtNmpwZmhoeDczeHZsbHBjNnVjbXIzeHJyNTBkdjVrcyJ9").unwrap(),
                signature: signature_raw.unwrap(),
                recovery_id: Some(1),
            };
            let cosmos_signature: CosmosSignature = from_binary(&sig.signature).unwrap();
            let res = cosmos_signature
                .derive_evm_addr_from_sig(deps.as_ref(), &sig.claim_msg, sig.recovery_id.unwrap())
                .unwrap();
            println!("eth recover: {:?}", res);
            assert_eq!(
                res.to_lowercase(),
                "0x27dd4328B9dD99281d398050B58EA0dbEc181E56".to_lowercase()
            );
        }

        #[test]
        fn claim_with_external_sigs() {
            let mut deps = mock_dependencies_with_balance(&[Coin {
                denom: "ujunox".to_string(),
                amount: Uint128::new(1234567),
            }]);
            let test_data: Encoded = from_slice(TEST_DATA_EXTERNAL_SIG).unwrap();
            let send_claim_addr = test_data
                .signed_msg
                .clone()
                .unwrap()
                .extract_addr()
                .unwrap();

            let msg = InstantiateMsg {
                default_admin: Some("owner0000".to_string()),
                cw20_token_address: None,
                native_token: Some("ujunox".to_string()),
            };

            let env = mock_env();
            let info = mock_info("addr0000", &[]);
            let _res = instantiate(deps.as_mut(), env, info, msg).unwrap();

            let env = mock_env();
            let info = mock_info("owner0000", &[]);
            let msg = ExecuteMsg::RegisterRoot {
                root: test_data.root,
                duration: Uint64::new(86400),
                hrp: Some("wasm".to_string()),
            };
            let _res = execute(deps.as_mut(), env, info, msg).unwrap();

            // cant claim without sig, info.sender is not present in the root
            let msg = ExecuteMsg::Claim {
                amount: test_data.amount,
                proof: test_data.proofs.clone(),
                sig_info: None,
            };

            let mut env = mock_env();
            env.block.time = env.block.time.plus_seconds(400);
            let info = mock_info(send_claim_addr.0.as_str(), &[]);
            let res = execute(deps.as_mut(), env, info, msg).unwrap_err();
            assert_eq!(res, ContractError::VerificationFailed {});

            // can claim with sig
            let msg = ExecuteMsg::Claim {
                amount: test_data.amount,
                proof: test_data.proofs,
                sig_info: test_data.signed_msg,
            };

            let env = mock_env();
            let info = mock_info(send_claim_addr.0.as_str(), &[]);
            let res = execute(deps.as_mut(), env.clone(), info.clone(), msg.clone()).unwrap();
            let expected = SubMsg::new(CosmosMsg::Bank(BankMsg::Send {
                to_address: send_claim_addr.0.clone(),
                amount: vec![Coin {
                    denom: "ujunox".to_string(),
                    amount: test_data.amount,
                }],
            }));

            assert_eq!(res.messages, vec![expected]);
            assert_eq!(
                res.events,
                vec![Event::new(EVENT_CLAIM)
                    .add_attribute("stage", "1")
                    .add_attribute("address", send_claim_addr.0.clone())
                    .add_attribute("amount", test_data.amount)]
            );

            // Check address is claimed
            assert!(
                from_binary::<ClaimedResponse>(
                    &query(
                        deps.as_ref(),
                        env.clone(),
                        QueryMsg::HasClaimed {
                            stage: 1,
                            users: vec![test_data.account.clone()],
                        },
                    )
                    .unwrap()
                )
                .unwrap()
                .claimed[0]
            );

            // check error on double claim
            let res = execute(deps.as_mut(), env.clone(), info, msg).unwrap_err();
            assert_eq!(res, ContractError::Claimed {});
        }
    }
}
