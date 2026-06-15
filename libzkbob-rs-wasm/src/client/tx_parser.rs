use libzkbob_rs::libzeropool::{
    native::{
        account::Account as NativeAccount,
        note::Note as NativeNote,
        cipher::{
            self,
            symcipher_decryption_keys,
            decrypt_account_no_validate,
            decrypt_note_no_validate, MessageEncryptionType
        },
        key::{
            self,derive_key_p_d
        }
    },
    fawkes_crypto::ff_uint::{ Num, NumRepr, Uint },
    constants,
};
use libzkbob_rs::{
    merkle::Hash,
    keys::Keys,
    utils::zero_account,
    delegated_deposit::{
        MEMO_DELEGATED_DEPOSIT_SIZE,
        MemoDelegatedDeposit
    }
};
use wasm_bindgen::{prelude::*, JsCast};
use serde::{Serialize, Deserialize};
use std::iter::IntoIterator;
use thiserror::Error;
use web_sys::console;
use crate::{ Account, Note };

#[cfg(feature = "multicore")]
use rayon::prelude::*;

use crate::{PoolParams, Fr, IndexedNote, IndexedTx, Fs,
            ParseTxsResult, POOL_PARAMS, helpers::vec_into_iter,
            TxMemoChunk,
        };

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Incorrect memo length at index {0}: no prefix")]
    NoPrefix(u64),
    #[error("Incorrect memo prefix at index {0}: got {1} items, max allowed {2}")]
    IncorrectPrefix(u64, u32, u32),
}

impl ParseError {
    pub fn _index(&self) -> u64 {
        match *self {
            ParseError::NoPrefix(idx)  => idx,
            ParseError::IncorrectPrefix(idx,  _, _)  => idx,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct StateUpdate {
    #[serde(rename = "newLeafs")]
    pub new_leafs: Vec<(u64, Vec<Hash<Fr>>)>,
    #[serde(rename = "newCommitments")]
    pub new_commitments: Vec<(u64, Hash<Fr>)>,
    #[serde(rename = "newAccounts")]
    pub new_accounts: Vec<(u64, NativeAccount<Fr>)>,
    #[serde(rename = "newNotes")]
    pub new_notes: Vec<Vec<(u64, NativeNote<Fr>)>>
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct DecMemo {
    pub index: u64,
    pub acc: Option<NativeAccount<Fr>>,
    #[serde(rename = "inNotes")]
    pub in_notes: Vec<IndexedNote>,
    #[serde(rename = "outNotes")]
    pub out_notes: Vec<IndexedNote>,
    #[serde(rename = "txHash")]
    pub tx_hash: Option<String>,
}

#[derive(Serialize, Default, Debug)]
pub struct ParseResult {
    #[serde(rename = "decryptedMemos")]
    pub decrypted_memos: Vec<DecMemo>,
    #[serde(rename = "stateUpdate")]
    pub state_update: StateUpdate
}
#[derive(Serialize, Default)]
pub struct ParseColdStorageResult {
    #[serde(rename = "decryptedMemos")]
    pub decrypted_memos: Vec<DecMemo>,
    #[serde(rename = "txCnt")]
    pub tx_cnt: usize,
    #[serde(rename = "decryptedLeafsCnt")]
    pub decrypted_leafs_cnt: usize,
}

/// Describes one memo chunk (account\note) along with decryption key
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct MemoChunk {
    pub index: u64,
    pub encrypted: Vec<u8>,
    pub key: Vec<u8>,
}

#[wasm_bindgen]
pub struct TxParser {
    #[wasm_bindgen(skip)]
    pub params: PoolParams,
}

#[wasm_bindgen]
impl TxParser {
    #[wasm_bindgen(js_name = "new")]
    pub fn new() -> Result<TxParser, JsValue> {
        Ok(TxParser{
            params: POOL_PARAMS.clone()
        })
    }

    #[wasm_bindgen(js_name = "parseTxs")]
    pub fn parse_txs(&self, sk: &[u8], txs: &JsValue) -> Result<ParseTxsResult, JsValue> {
        let sk = Num::<Fs>::from_uint(NumRepr(Uint::from_little_endian(sk)))
            .ok_or_else(|| js_err!("Invalid spending key"))?;
        let params = &self.params;
        let keys = Keys::derive(sk, params);
        let eta = keys.eta;
        let kappa = &keys.kappa;

        let txs: Vec<IndexedTx> = serde_wasm_bindgen::from_value(txs.to_owned()).map_err(|err| js_err!(&err.to_string()))?;

        let parse_results: Vec<_> = vec_into_iter(txs)
            .map(|tx| -> ParseResult {
                let IndexedTx{index, memo, commitment} = tx;
                let memo = hex::decode(memo).unwrap();
                let commitment = hex::decode(commitment).unwrap();
                
                match parse_tx(index, &commitment, &memo, None, &eta, kappa, params) {
                    Ok(res) => res,
                    Err(err) => {
                        console::log_1(&format!("[WASM TxParser] ERROR: {}", err.to_string()).into());
                        // Skip transaction in case of parsing errors (assume it doesn't belongs to the our account)
                        ParseResult {
                            state_update: StateUpdate {
                                new_commitments: vec![(
                                    index,
                                    Num::from_uint_reduced(NumRepr(Uint::from_big_endian(
                                        &commitment,
                                    ))),
                                )],
                                ..Default::default()
                            },
                            ..Default::default()
                        }
                    }
                }
            })
            .collect();

        let parse_result = parse_results
            .into_iter()
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

        let parse_result = serde_wasm_bindgen::to_value(&parse_result)
            .unwrap()
            .unchecked_into::<ParseTxsResult>();
        Ok(parse_result)
    }

    #[wasm_bindgen(js_name = "extractDecryptKeys")]
    pub fn extract_decrypt_keys(
        &self,
        sk: &[u8],
        index: u64,
        memo: &[u8],
    ) -> Result<Vec<TxMemoChunk>, JsValue> {
        let sk = Num::<Fs>::from_uint(NumRepr(Uint::from_little_endian(sk)))
            .ok_or_else(|| js_err!("Invalid spending key"))?;
        let keys = Keys::derive(sk, &self.params);
        let eta = keys.eta;
        let kappa = keys.kappa;
        //(index, chunk, key)
        let result = symcipher_decryption_keys(eta, &kappa, memo, &self.params).unwrap_or(vec![]);
    
        let chunks = result
        .iter()
        .map(|(chunk_idx, chunk, key)| {
            let res = MemoChunk {
                index: index + chunk_idx,
                encrypted: chunk.clone(),
                key: key.clone()
            };

            serde_wasm_bindgen::to_value(&res)
                .unwrap()
                .unchecked_into::<TxMemoChunk>()
        })
        .collect();
        
        Ok(chunks)

    }

    #[wasm_bindgen(js_name = "symcipherDecryptAcc")]
    pub fn symcipher_decrypt_acc(&self, sym_key: &[u8], encrypted: &[u8] ) -> Result<Account, JsValue> {
        let acc = decrypt_account_no_validate(sym_key, encrypted, &self.params)
                                .ok_or_else(|| js_err!("Unable to decrypt account"))?;
        
        Ok(serde_wasm_bindgen::to_value(&acc).unwrap().unchecked_into::<Account>())
    }

    #[wasm_bindgen(js_name = "symcipherDecryptNote")]
    pub fn symcipher_decrypt_note(&self, sym_key: &[u8], encrypted: &[u8] ) -> Result<Note, JsValue> {
        let note = decrypt_note_no_validate(sym_key, encrypted, &self.params)
                                .ok_or_else(|| js_err!("Unable to decrypt note"))?;
        
        Ok(serde_wasm_bindgen::to_value(&note).unwrap().unchecked_into::<Note>())
    }


}

pub fn parse_tx(
    index: u64,
    commitment: &Vec<u8>,
    memo: &Vec<u8>,
    tx_hash: Option<&Vec<u8>>,
    eta: &Num<Fr>,
    kappa: &[u8; 32],
    params: &PoolParams,
) -> Result<ParseResult, ParseError> {
    if memo.len() < 4 {
        return Err(ParseError::NoPrefix(index));
    }

    let (num_items, enc_type) =
        cipher::parse_memo_header(&mut memo.as_slice()).ok_or(ParseError::NoPrefix(index))?;

    if num_items > constants::OUT + 1 {
        return Err(ParseError::IncorrectPrefix(
            index,
            num_items as u32,
            (constants::OUT + 1) as u32,
        ));
    }

    match enc_type {
        
        MessageEncryptionType::Plain => {// Special case: transaction contains delegated deposits
            let num_deposits = num_items as usize;

            let delegated_deposits = memo[4..]
                .chunks(MEMO_DELEGATED_DEPOSIT_SIZE)
                .take(num_deposits)
                .map(|data| MemoDelegatedDeposit::read(data))
                .collect::<std::io::Result<Vec<_>>>()
                .unwrap();

            let in_notes_indexed = delegated_deposits
                .iter()
                .enumerate()
                .filter_map(|(i, d)| {
                    let p_d = derive_key_p_d(d.receiver_d.to_num(), eta.clone(), params).x;
                    if d.receiver_p == p_d {
                        Some(IndexedNote {
                            index: index + 1 + (i as u64),
                            note: d.to_delegated_deposit().to_note(),
                        })
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            let in_notes: Vec<_> = in_notes_indexed.iter().map(|n| (n.index, n.note)).collect();

            let hashes = [zero_account().hash(params)]
                .iter()
                .copied()
                .chain(
                    delegated_deposits
                        .iter()
                        .map(|d| d.to_delegated_deposit().to_note().hash(params)),
                )
                .collect();

            let parse_result = {
                if !in_notes.is_empty() {
                    ParseResult {
                        decrypted_memos: vec![DecMemo {
                            index,
                            in_notes: in_notes_indexed,
                            tx_hash: match tx_hash {
                                Some(bytes) => Some(format!("0x{}", hex::encode(bytes))),
                                _ => None,
                            },
                            ..Default::default()
                        }],
                        state_update: StateUpdate {
                            new_leafs: vec![(index, hashes)],
                            new_notes: vec![in_notes],
                            ..Default::default()
                        },
                    }
                } else {
                    ParseResult {
                        state_update: StateUpdate {
                            new_commitments: vec![(
                                index,
                                Num::from_uint_reduced(NumRepr(Uint::from_big_endian(&commitment))),
                            )],
                            ..Default::default()
                        },
                        ..Default::default()
                    }
                }
            };

            return Ok(parse_result);
        }
        MessageEncryptionType::Symmetric | MessageEncryptionType::ECDH => {// regular case: simple transaction memo
            let num_hashes = num_items;
            let hashes = (&memo[4..])
                .chunks(32)
                .take(num_hashes as usize)
                .map(|bytes| Num::from_uint_reduced(NumRepr(Uint::from_little_endian(bytes))));

            let pair = cipher::decrypt_out(*eta, kappa, &memo, params);

            match pair {
                Some((account, notes)) => {
                    let mut in_notes = Vec::new();
                    let mut out_notes = Vec::new();
                    notes.into_iter().enumerate().for_each(|(i, note)| {
                        out_notes.push((index + 1 + (i as u64), note));

                        if note.p_d == key::derive_key_p_d(note.d.to_num(), *eta, params).x {
                            in_notes.push((index + 1 + (i as u64), note));
                        }
                    });

                    Ok(ParseResult {
                        decrypted_memos: vec![DecMemo {
                            index,
                            acc: Some(account),
                            in_notes: in_notes
                                .iter()
                                .map(|(index, note)| IndexedNote {
                                    index: *index,
                                    note: *note,
                                })
                                .collect(),
                            out_notes: out_notes
                                .into_iter()
                                .map(|(index, note)| IndexedNote { index, note })
                                .collect(),
                            tx_hash: match tx_hash {
                                Some(bytes) => Some(format!("0x{}", hex::encode(bytes))),
                                _ => None,
                            },
                            ..Default::default()
                        }],
                        state_update: StateUpdate {
                            new_leafs: vec![(index, hashes.collect())],
                            new_accounts: vec![(index, account)],
                            new_notes: vec![in_notes],
                            ..Default::default()
                        },
                    })
                }
                None => {
                    let in_notes: Vec<(_, _)> = cipher::decrypt_in(*eta, &memo, params)
                        .into_iter()
                        .enumerate()
                        .filter_map(|(i, note)| match note {
                            Some(note)
                                if note.p_d
                                    == key::derive_key_p_d(note.d.to_num(), *eta, params).x =>
                            {
                                Some((index + 1 + (i as u64), note))
                            }
                            _ => None,
                        })
                        .collect();

                    if !in_notes.is_empty() {
                        Ok(ParseResult {
                            decrypted_memos: vec![DecMemo {
                                index,
                                in_notes: in_notes
                                    .iter()
                                    .map(|(index, note)| IndexedNote {
                                        index: *index,
                                        note: *note,
                                    })
                                    .collect(),
                                tx_hash: match tx_hash {
                                    Some(bytes) => Some(format!("0x{}", hex::encode(bytes))),
                                    None => None,
                                },
                                ..Default::default()
                            }],
                            state_update: StateUpdate {
                                new_leafs: vec![(index, hashes.collect())],
                                new_notes: vec![in_notes],
                                ..Default::default()
                            },
                        })
                    } else {
                        Ok(ParseResult {
                            state_update: StateUpdate {
                                new_commitments: vec![(
                                    index,
                                    Num::from_uint_reduced(NumRepr(Uint::from_big_endian(
                                        &commitment,
                                    ))),
                                )],
                                ..Default::default()
                            },
                            ..Default::default()
                        })
                    }
                }
            }
        }
    }
}