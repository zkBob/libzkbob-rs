use libzkbob_rs::libzeropool::constants;
use libzkbob_rs::libzeropool::fawkes_crypto::backend::bellman_groth16::engines::Bn256;
use libzkbob_rs::libzeropool::native::params::{PoolBN256, PoolParams as PoolParamsTrait};
use neon::prelude::*;
use serde::Serialize;

mod helpers;
mod keys;
mod merkle;
mod params;
mod proof;
mod storage;
mod tx;

pub type PoolParams = PoolBN256;
pub type Fr = <PoolParams as PoolParamsTrait>::Fr;
pub type Fs = <PoolParams as PoolParamsTrait>::Fs;
pub type Engine = Bn256;

#[allow(non_snake_case)]
#[derive(Serialize)]
struct Constants {
    HEIGHT: usize,
    IN: usize,
    OUTLOG: usize,
    OUT: usize,
    DELEGATED_DEPOSITS_NUM: usize,
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    let constants = neon_serde::to_value(
        &mut cx,
        &Constants {
            HEIGHT: constants::HEIGHT,
            IN: constants::IN,
            OUTLOG: constants::OUTPLUSONELOG,
            OUT: constants::OUT,
            DELEGATED_DEPOSITS_NUM: constants::DELEGATED_DEPOSITS_NUM,
        },
    )
    .unwrap();

    cx.export_value("Constants", constants)?;

    cx.export_function("readParamsFromBinary", params::from_binary)?;
    cx.export_function("readParamsFromFile", params::from_file)?;

    cx.export_function("proveTx", proof::prove_tx)?;
    cx.export_function("proveTree", proof::prove_tree)?;
    cx.export_function("proveDelegatedDeposit", proof::prove_delegated_deposit)?;
    cx.export_function("proveTxAsync", proof::prove_tx_async)?;
    cx.export_function("proveTreeAsync", proof::prove_tree_async)?;
    cx.export_function(
        "proveDelegatedDepositAsync",
        proof::prove_delegated_deposit_async,
    )?;
    cx.export_function("verify", proof::verify_proof)?;

    cx.export_function("merkleNew", merkle::merkle_new)?;
    cx.export_function("merkleGetRoot", merkle::merkle_get_root)?;
    cx.export_function("merkleGetNextIndex", merkle::merkle_get_next_index)?;
    cx.export_function("merkleGetNode", merkle::merkle_get_node)?;
    cx.export_function("merkleAddHash", merkle::merkle_add_hash)?;
    cx.export_function("merkleAddCommitment", merkle::merkle_add_commitment)?;
    cx.export_function("merkleAppendHash", merkle::merkle_append_hash)?;
    cx.export_function("merkleGetProof", merkle::merkle_get_leaf_proof)?;
    cx.export_function(
        "merkleGetCommitmentProof",
        merkle::merkle_get_commitment_proof,
    )?;
    cx.export_function("merkleGetAllNodes", merkle::merkle_get_all_nodes)?;
    cx.export_function("merkleGetVirtualNode", merkle::merkle_get_virtual_node)?;
    cx.export_function("merkleRollback", merkle::merkle_rollback)?;
    cx.export_function("merkleWipe", merkle::merkle_wipe)?;
    cx.export_function("merkleGetLeftSiblings", merkle::merkle_get_left_siblings)?;
    cx.export_function("merkleGetLastStableIndex", merkle::merkle_get_last_stable_index)?;
    cx.export_function("merkleSetLastStableIndex", merkle::merkle_set_last_stable_index)?;
    cx.export_function("merkleGetRootAt", merkle::merkle_get_root_at)?;

    cx.export_function("txStorageNew", storage::tx_storage_new)?;
    cx.export_function("txStorageAdd", storage::tx_storage_add)?;
    cx.export_function("txStorageDelete", storage::tx_storage_delete)?;
    cx.export_function("txStorageGet", storage::tx_storage_get)?;
    cx.export_function("txStorageCount", storage::tx_storage_count)?;

    cx.export_function("helpersOutCommitment", helpers::out_commitment)?;
    cx.export_function("helpersParseDelta", helpers::parse_delta_string)?;
    cx.export_function("helpersNumToStr", helpers::num_to_str)?;
    cx.export_function("helpersStrToNum", helpers::str_to_num)?;
    cx.export_function("helpersIsInPrimeSubgroup", helpers::is_in_prime_subgroup)?;
    
    cx.export_function("keysDerive", keys::keys_derive)?;

    cx.export_function(
        "createDelegatedDepositTxAsync",
        tx::create_delegated_deposit_tx_async,
    )?;

    cx.export_function(
        "delegatedDepositsToCommitment",
        tx::delegated_deposits_to_commitment,
    )?;

    Ok(())
}
