use std::collections::HashMap;
use std::rc::Rc;
use std::{cell::RefCell, convert::TryInto};
use std::str::FromStr;
#[cfg(feature = "multicore")]
use rayon::prelude::*;

use js_sys::{Array, Promise};
use libzkbob_rs::libzeropool::{
    constants,
    fawkes_crypto::{
        core::sizedvec::SizedVec,
        ff_uint::{Num, NumRepr, Uint},
        borsh::BorshDeserialize,
    },
    native::{
        account::Account as NativeAccount,
        note::Note as NativeNote,
        boundednum::BoundedNum,
        tx::{parse_delta, nullifier, TransferPub as NativeTransferPub, TransferSec as NativeTransferSec}
    },
};
use libzkbob_rs::{
    client::{TxType as NativeTxType, UserAccount as NativeUserAccount, StateFragment},
    merkle::{Hash, Node},
    address::{parse_address, parse_address_ext},
};

use serde::Serialize;
use wasm_bindgen::{prelude::*, JsCast };
use wasm_bindgen_futures::future_to_promise;

use crate::{ParseTxsColdStorageResult, IAddressComponents, TxInput, TxInputNodes, IndexedAccount};
use crate::client::tx_parser::StateUpdate;

use crate::database::Database;
use crate::helpers::vec_into_iter;
use crate::ts_types::Hash as JsHash;
use crate::{
    Account, Fr, Fs, Hashes, 
    IDepositData, IDepositPermittableData, ITransferData, IWithdrawData,
    IndexedNote, IndexedNotes, PoolParams, Transaction, UserState, POOL_PARAMS,
    MerkleProof, Pair, TreeNode, TreeNodes,
};
use tx_types::JsTxType;
use crate::client::coldstorage::BulkData;
use crate::client::tx_parser::{ ParseResult, ParseColdStorageResult };

mod tx_types;
mod coldstorage;
mod tx_parser;


// TODO: Find a way to expose MerkleTree,

#[wasm_bindgen]
pub struct UserAccount {
    inner: Rc<RefCell<NativeUserAccount<Database, PoolParams>>>,
}

#[wasm_bindgen]
impl UserAccount {
    #[wasm_bindgen(constructor)]
    /// Initializes UserAccount with a spending key that has to be an element of the prime field Fs (p = 6554484396890773809930967563523245729705921265872317281365359162392183254199).
    pub fn new(sk: &[u8], pool_id: u32, is_obsolete_pool: bool, state: UserState) -> Result<UserAccount, JsValue> {
        crate::utils::set_panic_hook();
        let sk = Num::<Fs>::from_uint(NumRepr(Uint::from_little_endian(sk)))
            .ok_or_else(|| js_err!("Invalid spending key"))?;

        let account = NativeUserAccount::new(sk, pool_id, is_obsolete_pool, state.inner, POOL_PARAMS.clone());

        Ok(UserAccount {
            inner: Rc::new(RefCell::new(account)),
        })
    }

    #[wasm_bindgen(js_name = "generateAddress")]
    /// Generates a new private address for the current pool
    pub fn generate_address(&self) -> String {
        self.inner.borrow().generate_address()
    }

    #[wasm_bindgen(js_name = "generateUniversalAddress")]
    /// Generates a new private address for any pool
    pub fn generate_universal_address(&self) -> String {
        self.inner.borrow().generate_universal_address()
    }

    #[wasm_bindgen(js_name = "generateAddressForSeed")]
    pub fn generate_address_for_seed(&self, seed: &[u8]) -> String {
        self.inner.borrow().gen_address_for_seed(seed)
    }

    #[wasm_bindgen(js_name = "generateUniversalAddressForSeed")]
    pub fn generate_universal_address_for_seed(&self, seed: &[u8]) -> String {
        self.inner.borrow().gen_universal_address_for_seed(seed)
    }

    #[wasm_bindgen(js_name = "validateAddress")]
    pub fn validate_address(&self, address: &str) -> bool {
        self.inner.borrow().validate_address(address)
    }

    #[wasm_bindgen(js_name = "validateUniversalAddress")]
    pub fn validate_universal_address(&self, address: &str) -> bool {
        self.inner.borrow().validate_universal_address(address)
    }

    #[wasm_bindgen(js_name = "assembleAddress")]
    pub fn assemble_address(&self, d: &str, p_d: &str) -> String {
        let d = Num::from_str(d).unwrap();
        let d = BoundedNum::new(d);
        let p_d = Num::from_str(p_d).unwrap();

        self.inner.borrow().generate_address_from_components(d, p_d)
    }

    #[wasm_bindgen(js_name = "assembleUniversalAddress")]
    pub fn assemble_universal_address(&self, d: &str, p_d: &str) -> String {
        let d = Num::from_str(d).unwrap();
        let d = BoundedNum::new(d);
        let p_d = Num::from_str(p_d).unwrap();

        self.inner.borrow().generate_universal_address_from_components(d, p_d)
    }

    #[wasm_bindgen(js_name = "convertAddressToChainSpecific")]
    pub fn convert_address_to_chain_specific(&self, address: &str) -> Result<String, JsValue> {
        let (d, p_d, _) = 
            parse_address::<PoolParams>(address, &POOL_PARAMS, self.inner.borrow().pool_id).map_err(|err| js_err!(&err.to_string()))?;

        Ok(self.inner.borrow().generate_address_from_components(d, p_d))
    }

    #[wasm_bindgen(js_name = "parseAddress")]
    pub fn parse_address(&self, address: &str, pool_id: Option<u32>) -> Result<IAddressComponents, JsValue> {
        let desired_pool_id = pool_id.unwrap_or(self.inner.borrow().pool_id);
        let (d, p_d, pool, format, checksum) = 
            parse_address_ext::<PoolParams>(address, &POOL_PARAMS, desired_pool_id).map_err(|err| js_err!(&err.to_string()))?;

        #[derive(Serialize)]
        struct Address {
            format: String,
            d: String,
            p_d: String,
            checksum: [u8; 4],
            pool_id: String,
            derived_from_our_sk: bool,
            is_pool_valid: bool,
        }

        let address = Address {
            format: format.name().to_string(),
            d: d.to_num().to_string(),
            p_d: p_d.to_string(),
            checksum,
            pool_id: if let Some(pool) = pool { format!("{}", pool) } else { "any".to_string() },
            derived_from_our_sk: self.inner.borrow().is_derived_from_our_sk(d, p_d),
            is_pool_valid: if let Some(pool) = pool { pool == self.inner.borrow().pool_id } else { true },
        };

        Ok(serde_wasm_bindgen::to_value(&address)
            .unwrap()
            .unchecked_into::<IAddressComponents>())
    }

    #[wasm_bindgen(js_name = "calculateNullifier")]
    /// Calculate nullifier from the account
    pub fn calculate_nullifier(&self, account: Account, index: u64) -> Result<JsHash, JsValue> {
        let in_account: NativeAccount<Fr> = serde_wasm_bindgen::from_value(account.into())?;

        let params = &self.inner.borrow().params;
        let eta = &self.inner.borrow().keys.eta;
        let in_account_hash = in_account.hash(params);
        let nullifier = nullifier(
            in_account_hash,
            *eta,
            index.into(),
            params,
        );

        Ok(serde_wasm_bindgen::to_value(&nullifier)
                    .unwrap()
                    .unchecked_into::<JsHash>())
    }

    #[wasm_bindgen(js_name = decryptNotes)]
    /// Attempts to decrypt notes.
    pub fn decrypt_notes(&self, data: Vec<u8>) -> Result<IndexedNotes, JsValue> {
        let notes = self
            .inner
            .borrow()
            .decrypt_notes(data)
            .into_iter()
            .enumerate()
            .filter_map(|(index, note)| {
                let note = IndexedNote {
                    index: index as u64,
                    note: note?,
                };

                Some(serde_wasm_bindgen::to_value(&note).unwrap())
            })
            .collect::<Array>()
            .unchecked_into::<IndexedNotes>();

        Ok(notes)
    }

    #[wasm_bindgen(js_name = "decryptPair")]
    /// Attempts to decrypt account and notes.
    pub fn decrypt_pair(&self, data: Vec<u8>) -> Result<Option<Pair>, JsValue> {
        #[derive(Serialize)]
        struct SerPair {
            account: NativeAccount<Fr>,
            notes: Vec<NativeNote<Fr>>,
        }

        let pair = self
            .inner
            .borrow()
            .decrypt_pair(data)
            .map(|(account, notes)| {
                let pair = SerPair { account, notes };

                serde_wasm_bindgen::to_value(&pair)
                    .unwrap()
                    .unchecked_into::<Pair>()
            });

        Ok(pair)
    }

    fn construct_tx_data(&self, native_tx: NativeTxType<Fr>, new_state: Option<StateUpdate>) -> Promise {
        #[derive(Serialize)]
        struct ParsedDelta {
            v: i64,
            e: i64,
            index: u64,
        }

        #[derive(Serialize)]
        struct TransactionData {
            public: NativeTransferPub<Fr>,
            secret: NativeTransferSec<Fr>,
            #[serde(with = "hex")]
            ciphertext: Vec<u8>,
            #[serde(with = "hex")]
            memo: Vec<u8>,
            commitment_root: Num<Fr>,
            out_hashes: SizedVec<Num<Fr>, { constants::OUT + 1 }>,
            parsed_delta: ParsedDelta,
        }

        let account = self.inner.clone();

        let extra_state = new_state.map(|s| {
            let mut joined_notes = vec![];
            s.new_notes.into_iter().for_each(|notes| {
                notes.into_iter().for_each(|one_note| {
                    joined_notes.push(one_note);
                });
            });

            StateFragment {
                new_leafs: s.new_leafs,
                new_commitments: s.new_commitments,
                new_accounts: s.new_accounts,
                new_notes: joined_notes,
            }
        });

        future_to_promise(async move {
            let tx = account
                .borrow()
                .create_tx(native_tx, None, extra_state)
                .map_err(|err| js_err!("{}", err))?;

            let (v, e, index, _) = parse_delta(tx.public.delta);
            let parsed_delta = ParsedDelta {
                v: v.try_into().unwrap(),
                e: e.try_into().unwrap(),
                index: index.try_into().unwrap(),
            };

            let tx = TransactionData {
                public: tx.public,
                secret: tx.secret,
                ciphertext: tx.ciphertext,
                memo: tx.memo,
                out_hashes: tx.out_hashes,
                commitment_root: tx.commitment_root,
                parsed_delta,
            };

            Ok(serde_wasm_bindgen::to_value(&tx).unwrap())
        })
    }

    #[wasm_bindgen(js_name = "createDeposit")]
    pub fn create_deposit(&self, deposit: IDepositData) -> Result<Promise, JsValue> {
        Ok(self.construct_tx_data(deposit.to_native()?, None))
    }

    #[wasm_bindgen(js_name = "createDepositPermittable")]
    pub fn create_deposit_permittable(&self, deposit: IDepositPermittableData) -> Result<Promise, JsValue> {
        Ok(self.construct_tx_data(deposit.to_native()?, None))
    }

    #[wasm_bindgen(js_name = "createTransfer")]
    pub fn create_tranfer(&self, transfer: ITransferData) -> Result<Promise, JsValue> {
        Ok(self.construct_tx_data(transfer.to_native()?, None))
    }

    #[wasm_bindgen(js_name = "createTransferOptimistic")]
    pub fn create_tranfer_optimistic(&self, transfer: ITransferData, new_state: &JsValue) -> Result<Promise, JsValue> {
        let new_state: StateUpdate = serde_wasm_bindgen::from_value(new_state.to_owned()).map_err(|err| js_err!(&err.to_string()))?;
        Ok(self.construct_tx_data(transfer.to_native()?, Some(new_state)))
    }

    #[wasm_bindgen(js_name = "createWithdraw")]
    pub fn create_withdraw(&self, withdraw: IWithdrawData) -> Result<Promise, JsValue> {
        Ok(self.construct_tx_data(withdraw.to_native()?, None))
    }

    #[wasm_bindgen(js_name = "createWithdrawalOptimistic")]
    pub fn create_withdraw_optimistic(&self, withdraw: IWithdrawData, new_state: &JsValue) -> Result<Promise, JsValue> {
        let new_state: StateUpdate = serde_wasm_bindgen::from_value(new_state.to_owned()).map_err(|err| js_err!(&err.to_string()))?;
        Ok(self.construct_tx_data(withdraw.to_native()?, Some(new_state)))
    }

    #[wasm_bindgen(js_name = "isOwnAddress")]
    pub fn is_own_address(&self, address: &str) -> bool {
        self.inner.borrow().is_own_address(address)
    }

    #[wasm_bindgen(js_name = "addCommitment")]
    /// Add out commitment hash to the tree.
    pub fn add_commitment(&mut self, index: u64, commitment: Vec<u8>) -> Result<(), JsValue> {
        self.inner.borrow_mut().state.tree.add_hash_at_height(
            constants::OUTPLUSONELOG as u32,
            index,
            Num::try_from_slice(commitment.as_slice()).unwrap(),
            false,
        );

        Ok(())
    }

    #[wasm_bindgen(js_name = "addAccount")]
    /// Cache account and notes (own tx) at specified index.
    pub fn add_account(
        &mut self,
        at_index: u64,
        hashes: Hashes,
        account: Account,
        notes: IndexedNotes,
    ) -> Result<(), JsValue> {
        let account = serde_wasm_bindgen::from_value(account.into())?;
        let hashes: Vec<_> = serde_wasm_bindgen::from_value(hashes.unchecked_into())?;
        let notes: Vec<_> =
            serde_wasm_bindgen::from_value::<Vec<IndexedNote>>(notes.unchecked_into())?
                .into_iter()
                .map(|note| (note.index, note.note))
                .collect();

        self.inner
            .borrow_mut()
            .state
            .add_full_tx(at_index, &hashes, account, &notes);

        Ok(())
    }

    #[wasm_bindgen(js_name = "addHashes")]
    /// Cache tx hashes at specified index.
    pub fn add_hashes(&mut self, at_index: u64, hashes: Hashes) -> Result<(), JsValue> {
        let hashes: Vec<_> = serde_wasm_bindgen::from_value(hashes.unchecked_into())?;

        self.inner.borrow_mut().state.add_hashes(at_index, &hashes);

        Ok(())
    }

    #[wasm_bindgen(js_name = "addNotes")]
    /// Cache only notes at specified index
    pub fn add_notes(
        &mut self,
        at_index: u64,
        hashes: Hashes,
        notes: IndexedNotes,
    ) -> Result<(), JsValue> {
        let hashes: Vec<_> = serde_wasm_bindgen::from_value(hashes.unchecked_into())?;
        let notes: Vec<_> =
            serde_wasm_bindgen::from_value::<Vec<IndexedNote>>(notes.unchecked_into())?
                .into_iter()
                .map(|note| (note.index, note.note))
                .collect();

        self.inner
            .borrow_mut()
            .state
            .add_full_tx(at_index, &hashes, None, &notes);

        Ok(())
    }

    #[wasm_bindgen(js_name = "updateState")]
    pub fn update_state(&mut self, state_update: &JsValue, siblings: Option<TreeNodes>) -> Result<(), JsValue> {
        let state_update: StateUpdate = serde_wasm_bindgen::from_value(state_update.to_owned()).map_err(|err| js_err!(&err.to_string()))?;
        let siblings: Option<Vec<Node<Fr>>> = match siblings {
            Some(val) => serde_wasm_bindgen::from_value(val.unchecked_into()).map_err(|err| js_err!(&err.to_string()))?,
            None => None
        };
        
        Ok(self.update_state_internal(state_update, siblings))
    }

    fn update_state_internal(&mut self, state_update: StateUpdate, siblings: Option<Vec<Node<Fr>>>) -> () {
        if !state_update.new_leafs.is_empty() || !state_update.new_commitments.is_empty() {
            self.inner.borrow_mut()
                .state
                .tree
                .add_leafs_commitments_and_siblings(
                    state_update.new_leafs,
                    state_update.new_commitments,
                    siblings
                );
        }

        state_update.new_accounts.into_iter().for_each(|(at_index, account)| {
            self.inner.borrow_mut().state.add_account(at_index, account);
        });

        state_update.new_notes.into_iter().for_each(|notes| {
            notes.into_iter().for_each(|(at_index, note)| {
                self.inner.borrow_mut().state.add_note(at_index, note);
            });
        });

        ()
    }

    
    #[wasm_bindgen(js_name = "updateStateColdStorage")]
    pub fn update_state_cold_storage(
        &mut self,
        bulks: Vec<js_sys::Uint8Array>,
        from_index: Option<u64>,    // inclusively
        to_index: Option<u64>,      // exclusively
    ) -> Result<ParseTxsColdStorageResult, JsValue> {
        const MAX_SUPPORTED_BULK_VERSION: u8 = 1;

        let mut total_txs_cnt: usize = 0;
        let bulks_obj: Result<Vec<BulkData>, JsValue> = bulks.into_iter().map(|array| {
            let bulk_data = array.to_vec();
            let bulk: BulkData = match bincode::deserialize(&bulk_data) {
                Ok(res) => res,
                Err(e) => return Err(js_err!(&format!("Cannot parse bulk data: {}", e))),
            };

            if bulk.bulk_version > MAX_SUPPORTED_BULK_VERSION {
                return Err(js_err!(&format!("Incorrect bluk vesion {}, supported {}", bulk.bulk_version, MAX_SUPPORTED_BULK_VERSION)))
            }

            Ok(bulk)
        })
        .collect();

        if let Err(e) = bulks_obj {
            return Err(e);
        }


        let mut single_result: ParseResult = bulks_obj
            .unwrap()
            .into_iter()
            .map(|bulk| -> Vec<ParseResult> {
                let eta = &self.inner.borrow().keys.eta;
                let kappa = &self.inner.borrow().keys.kappa;
                let params = &self.inner.borrow().params;
                let range = from_index.unwrap_or(0)..to_index.unwrap_or(u64::MAX);
                let bulk_results: Vec<ParseResult> = vec_into_iter(bulk.txs)
                    .filter(|tx| range.contains(&tx.index))
                    .filter_map(|tx| -> Option<ParseResult> {
                        tx_parser::parse_tx(
                            tx.index,
                            &tx.commitment,
                            &tx.memo,
                            Some(&tx.tx_hash),
                            eta,
                            kappa,
                            params
                        ).ok()
                    })
                    .collect();
                
                total_txs_cnt = total_txs_cnt + bulk_results.len();

                bulk_results
            })
            .flatten()
            .fold(Default::default(), |acc: ParseResult, parse_result| {
                ParseResult {
                    decrypted_memos: vec![acc.decrypted_memos, parse_result.decrypted_memos].concat(),
                    state_update: StateUpdate {
                        new_leafs: vec![acc.state_update.new_leafs, parse_result.state_update.new_leafs].concat(),
                        new_commitments: vec![acc.state_update.new_commitments, parse_result.state_update.new_commitments].concat(),
                        new_accounts: vec![acc.state_update.new_accounts, parse_result.state_update.new_accounts].concat(),
                        new_notes: vec![acc.state_update.new_notes, parse_result.state_update.new_notes].concat()
                    }
                }
            });

        let decrypted_leafs_cnt: usize = single_result.state_update.new_leafs.len();

        self.update_state_internal(single_result.state_update, None);

        
        single_result.decrypted_memos.sort_by(|a,b| a.index.cmp(&b.index));
        
        let sync_result = ParseColdStorageResult {
            decrypted_memos: single_result.decrypted_memos,
            tx_cnt: total_txs_cnt,
            decrypted_leafs_cnt: decrypted_leafs_cnt,
        };

        let sync_result = serde_wasm_bindgen::to_value(&sync_result)
            .unwrap()
            .unchecked_into::<ParseTxsColdStorageResult>();

        Ok(sync_result)
    }

    #[wasm_bindgen(js_name = "getRoot")]
    pub fn get_root(&mut self) -> String {
        let root = self.inner.borrow_mut().state.tree.get_root().to_string();

        root
    }

    #[wasm_bindgen(js_name = "getRootAt")]
    pub fn get_root_at(&mut self, index: u64) -> Result<String, JsValue> {

        match self.inner.borrow_mut().state.tree.get_root_at(index) {
            Some(val) => Ok(val.to_string()),
            None => Err(js_err!(&format!("Tree doesn't contain sufficient data to calculate root at index {}", index)))
        }
    }

    #[wasm_bindgen(js_name = "totalBalance")]
    /// Returns user's total balance (account + available notes).
    pub fn total_balance(&self) -> String {
        self.inner.borrow().state.total_balance().to_string()
    }

    #[wasm_bindgen(js_name = "accountBalance")]
    /// Returns user's total balance (account + available notes).
    pub fn account_balance(&self) -> String {
        self.inner.borrow().state.account_balance().to_string()
    }

    #[wasm_bindgen(js_name = "noteBalance")]
    /// Returns user's total balance (account + available notes).
    pub fn note_balance(&self) -> String {
        self.inner.borrow().state.note_balance().to_string()
    }

    #[wasm_bindgen(js_name = "getUsableNotes")]
    /// Returns all notes available for spending
    pub fn get_usable_notes(&self) -> JsValue {
        let data = self.inner.borrow().state.get_usable_notes();

        serde_wasm_bindgen::to_value(&data).unwrap()
    }

    #[wasm_bindgen(js_name = "getTxInputs")]
    /// Returns transaction inputs: account and notes
    pub fn get_tx_inputs(&self, index: u64) -> Result<TxInput, JsValue> {
        if index & constants::OUT as u64 != 0 {
            return Err(js_err!(&format!("Account index should be multiple of {}", constants::OUT + 1)));
        }

        let inputs = self
            .inner
            .borrow()
            .get_tx_input(index)
            .ok_or_else(|| js_err!("No account found at index {}", index))?;
            
        let res = TxInputNodes {
            account: IndexedAccount {
                index: inputs.account.0,
                account: inputs.account.1
            },
            intermediate_nullifier: inputs.intermediate_nullifier,
            notes:  inputs
                    .notes.into_iter()
                    .map(|note| {
                        IndexedNote {
                            index: note.0,
                            note: note.1,
                        }
                    })
                    .collect()
        };

        Ok(serde_wasm_bindgen::to_value(&res)
            .unwrap()
            .unchecked_into::<TxInput>())
    }

    #[wasm_bindgen(js_name = "nextTreeIndex")]
    pub fn next_tree_index(&self) -> u64 {
        self.inner.borrow().state.tree.next_index()
    }

    #[wasm_bindgen(js_name = "firstTreeIndex")]
    pub fn first_tree_index(&self) -> Option<u64> {
        self.inner.borrow().state.tree.first_index()
    }

    // TODO: Temporary method, try to expose the whole tree
    #[wasm_bindgen(js_name = "getLastLeaf")]
    pub fn get_last_leaf(&self) -> String {
        self.inner.borrow().state.tree.last_leaf().to_string()
    }

    #[wasm_bindgen(js_name = "getMerkleNode")]
    pub fn get_merkle_node(&self, height: u32, index: u64) -> String {
        let node = self.inner.borrow().state.tree.get(height, index);

        node.to_string()
    }

    #[wasm_bindgen(js_name = "getLeftSiblings")]
    pub fn get_left_siblings(&self, index: u64) -> Result<Vec<TreeNode>, JsValue> {
        if index & constants::OUTPLUSONELOG as u64 != 0 {
            return Err(js_err!(&format!("Index to creating sibling from should be multiple of {}", constants::OUT + 1)));
        }

        let siblings = self
            .inner
            .borrow()
            .state
            .tree
            .get_left_siblings(index);

        
        match siblings {
            Some(val) => {
                let result = val
                    .into_iter()
                    .map(|node| {
                        serde_wasm_bindgen::to_value(&node)
                            .unwrap()
                            .unchecked_into::<TreeNode>()
                    })
                    .collect();
                
                Ok(result)
            },
            None => Err(js_err!(&format!("Tree is undefined at index {}", index)))
        }
        
            
    }

    #[wasm_bindgen(js_name = "getMerkleProof")]
    /// Returns merkle proof for the specified index in the tree.
    pub fn get_merkle_proof(&self, index: u64) -> MerkleProof {
        let proof = self
            .inner
            .borrow()
            .state
            .tree
            .get_proof_unchecked::<{ constants::HEIGHT }>(index);

        serde_wasm_bindgen::to_value(&proof)
            .unwrap()
            .unchecked_into::<MerkleProof>()
    }

    // TODO: This is a temporary method
    #[wasm_bindgen(js_name = "getMerkleRootAfterCommitment")]
    pub fn get_merkle_root_after_commitment(
        &self,
        commitment_index: u64,
        commitment: JsHash,
    ) -> Result<String, JsValue> {
        let hash: Hash<Fr> = serde_wasm_bindgen::from_value(commitment.unchecked_into())?;
        let mut nodes = HashMap::new();
        nodes.insert((constants::OUTPLUSONELOG as u32, commitment_index), hash);

        let left_index = commitment_index * (2u64.pow(constants::OUTPLUSONELOG as u32));
        let node = self.inner.borrow().state.tree.get_virtual_node(
            constants::HEIGHT as u32,
            0,
            &mut nodes,
            left_index,
            left_index + constants::OUT as u64 + 1,
        );

        Ok(node.to_string())
    }

    #[wasm_bindgen(js_name = "getMerkleProofAfter")]
    /// Returns merkle proofs for the specified leafs (hashes) as if they were appended to the tree.
    pub fn get_merkle_proof_after(&self, hashes: Hashes) -> Result<Vec<MerkleProof>, JsValue> {
        let hashes: Vec<Hash<Fr>> = serde_wasm_bindgen::from_value(hashes.unchecked_into())?;

        let proofs = self
            .inner
            .borrow_mut()
            .state
            .tree
            .get_proof_after_virtual(hashes)
            .into_iter()
            .map(|proof| {
                serde_wasm_bindgen::to_value(&proof)
                    .unwrap()
                    .unchecked_into::<MerkleProof>()
            })
            .collect();

        Ok(proofs)
    }

    #[wasm_bindgen(js_name = "getCommitmentMerkleProof")]
    pub fn get_commitment_merkle_proof(&self, index: u64) -> MerkleProof {
        let proof = self
            .inner
            .borrow()
            .state
            .tree
            .get_proof_unchecked::<{ constants::HEIGHT - constants::OUTPLUSONELOG }>(index);

        serde_wasm_bindgen::to_value(&proof)
            .unwrap()
            .unchecked_into::<MerkleProof>()
    }

    #[wasm_bindgen(js_name = "getWholeState")]
    pub fn get_whole_state(&self) -> JsValue {
        #[derive(Serialize)]
        struct WholeState {
            nodes: Vec<Node<Fr>>,
            txs: Vec<(u64, Transaction)>,
        }

        let state = &self.inner.borrow().state;
        let nodes = state.tree.get_all_nodes();
        let txs = state
            .get_all_txs()
            .into_iter()
            .map(|(i, tx)| (i, tx.into()))
            .collect();

        let data = WholeState { nodes, txs };

        serde_wasm_bindgen::to_value(&data).unwrap()
    }

    #[wasm_bindgen(js_name = "rollbackState")]
    pub fn rollback_state(&self, rollback_index: u64) -> u64 {
        self.inner.borrow_mut().state.rollback(rollback_index)
    }

    #[wasm_bindgen(js_name = "wipeState")]
    pub fn wipe_state(&self) {
        self.inner.borrow_mut().state.wipe();
    }

    #[wasm_bindgen(js_name = "treeGetStableIndex")]
    pub fn tree_get_stable_index(&self) -> u64 {
        self.inner.borrow_mut().state.tree.get_last_stable_index()
    }

    #[wasm_bindgen(js_name = "treeSetStableIndex")]
    pub fn tree_set_stable_index(&self, stable_index: u64) {
        self.inner.borrow_mut().state.tree.set_last_stable_index(Some(stable_index));
    }

    #[wasm_bindgen(js_name = "accountNullifier")]
    pub fn get_last_account_nullifier(&self)  -> Result<JsHash, JsValue> {
        let inner = self.inner.borrow();
        let latest_acc = match inner.state.latest_account_index {
            Some(acc_idx) => (acc_idx, inner.state.get_account(acc_idx)
                                            .unwrap_or_else(|| inner.initial_account())),
            None => (0 as u64, inner.initial_account()),
        };


        let params = &inner.params;
        let eta = &inner.keys.eta;
        let in_account_hash = latest_acc.1.hash(params);
        let nullifier = nullifier(
            in_account_hash,
            *eta,
            latest_acc.0.into(),
            params,
        );

        Ok(serde_wasm_bindgen::to_value(&nullifier)
                    .unwrap()
                    .unchecked_into::<JsHash>())
        
    }
}
