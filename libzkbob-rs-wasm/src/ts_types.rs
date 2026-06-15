use fawkes_crypto::ff_uint::Num;
use libzkbob_rs::libzeropool::native::{
    note::Note as NativeNote,
    account::Account as NativeAccount,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::Fr;

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &'static str = r#"
export class Constants {
  HEIGHT: number;
  IN: number;
  OUT: number;
  OUTLOG: number;
}

export interface Note {
    d: string;
    p_d: string;
    b: string;
    t: string;
}

export interface Account {
    d: string;
    p_d: string;
    i: string;
    b: string;
    e: string;
}

export interface TransferPub {
    root: string;
    nullifier: string;
    out_commit: string;
    delta: string;
    memo: string;
}

export interface TransferSec {
    tx: Tx;
    in_proof: { account: MerkleProof; notes: Array<MerkleProof> };
    eddsa_s: string;
    eddsa_r: string;
    eddsa_a: string;
}

export interface TransactionData {
    public: TransferPub;
    secret: TransferSec;
    ciphertext: string;
    memo: string;
    out_hashes: string[];
    commitment_root: string;
    parsed_delta: { v: string; e: string; index: string; };
}

export interface TreePub {
    root_before: string;
    root_after: string;
    leaf: string;
}

export interface TreeSec {
    proof_filled: MerkleProof;
    proof_free: MerkleProof;
    prev_leaf: string;
}

export interface Tx {
    input: [Account, Note[]];
    output: [Account, Note[]];
}

export interface Output {
    to: string;
    amount: string;
}

export interface MerkleProof {
    sibling: string[];
    path: boolean[];
}

export interface TreeNode {
    index: number;
    height: number;
    value: string;
}

export interface Proof {
    inputs: string[];
    proof: SnarkProof;
}

export interface SnarkProof {
    a: [string, string];
    b: [[string, string], [string, string]];
    c: [string, string];
}
export interface VK {
    alpha: string[];   // G1
    beta: string[][];  // G2
    gamma: string[][]; // G2
    delta: string[][]; // G2
    ic: string[][];    // G1[]
}

export interface IAddressComponents {
    format: string;
    d: string;
    p_d: string;
    checksum: Uint8Array;
    pool_id: string;
    derived_from_our_sk: boolean;
    is_pool_valid: boolean;
}

export interface IExtraItem {
    leaf_index: number;
    pad_length: number;
    need_encrypt: boolean;
    data: Uint8Array;
}

export interface ITxBaseFields {
    proxy: Uint8Array;
    prover: Uint8Array;
    proxy_fee: string;
    prover_fee: string;
    data: IExtraItem[];
}

export interface IDepositData extends ITxBaseFields {
    amount: string;
}

export interface IDepositPermittableData extends ITxBaseFields {
    amount: string;
    deadline: string;
    holder: Uint8Array;
}

export interface ITransferData extends ITxBaseFields {
    outputs: Output[];
}

export interface IWithdrawData extends ITxBaseFields {
    amount: string;
    to: Uint8Array;
    native_amount: string;
    energy_amount: string;
}

export interface DecryptedMemo {
    index: number;
    acc: Account | undefined;
    inNotes:  { note: Note, index: number }[];
    outNotes: { note: Note, index: number }[];
    txHash: string | undefined;
}

export interface StateUpdate {
    newLeafs: any[];
    newCommitments: any[];
    newAccounts: any[];
    newNotes: any[][];
}

export interface IndexedTx {
    index: number;
    memo: string;
    commitment: string;
}

export interface ParseTxsResult {
    decryptedMemos: DecryptedMemo[];
    stateUpdate: StateUpdate;
}

export interface ParseTxsColdStorageResult {
    decryptedMemos: DecryptedMemo[];
    txCnt: number;
    decryptedLeafsCnt: number;
}

export interface TxMemoChunk {
    index: number;
    encrypted: Uint8Array;
    key: Uint8Array;
}

export interface TxInput {
    account: { index: number, account: Account };
    intermediateNullifier: string
    notes: { index: number, note: Note }[];
}

"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Note[]")]
    pub type Notes;

    #[wasm_bindgen(typescript_type = "{ note: Note, index: number }[]")]
    pub type IndexedNotes;

    #[wasm_bindgen(typescript_type = "MerkleProof")]
    pub type MerkleProof;

    #[wasm_bindgen(typescript_type = "string[]")]
    pub type MerkleProofSibling;

    #[wasm_bindgen(typescript_type = "boolean[]")]
    pub type MerkleProofPath;

    #[wasm_bindgen(typescript_type = "Array<Output> | string")]
    pub type TxOutputs;

    #[wasm_bindgen(typescript_type = "Note")]
    pub type Note;

    #[wasm_bindgen(typescript_type = "Account")]
    pub type Account;

    #[wasm_bindgen(typescript_type = "{ account: Account; notes: Array<Note> }")]
    pub type Pair;

    #[wasm_bindgen(typescript_type = "TransferPub")]
    pub type TransferPub;

    #[wasm_bindgen(typescript_type = "TransferSec")]
    pub type TransferSec;

    #[wasm_bindgen(typescript_type = "TreePub")]
    pub type TreePub;

    #[wasm_bindgen(typescript_type = "TreeSec")]
    pub type TreeSec;

    #[wasm_bindgen(typescript_type = "TreeNode")]
    pub type TreeNode;

    #[wasm_bindgen(typescript_type = "TreeNode[]")]
    pub type TreeNodes;

    #[wasm_bindgen(typescript_type = "Proof")]
    pub type Proof;

    #[wasm_bindgen(typescript_type = "SnarkProof")]
    pub type SnarkProof;

    #[wasm_bindgen(typescript_type = "string[]")]
    pub type SnarkInputs;

    #[wasm_bindgen(typescript_type = "VK")]
    pub type VK;

    #[wasm_bindgen(typescript_type = "TransactionData")]
    pub type TransactionData;

    #[wasm_bindgen(typescript_type = "Constants")]
    pub type Constants;

    #[wasm_bindgen(typescript_type = "string[]")]
    pub type Hashes;

    #[wasm_bindgen(typescript_type = "string")]
    pub type Hash;

    #[wasm_bindgen(typescript_type = "Array<Uint8Array>")]
    pub type RawHashes;

    #[wasm_bindgen(typescript_type = "IDepositData")]
    pub type IDepositData;

    #[wasm_bindgen(typescript_type = "IDepositPermittableData")]
    pub type IDepositPermittableData;

    #[wasm_bindgen(typescript_type = "ITransferData")]
    pub type ITransferData;

    #[wasm_bindgen(typescript_type = "IWithdrawData")]
    pub type IWithdrawData;

    #[wasm_bindgen(typescript_type = "DecryptedMemo")]
    pub type DecryptedMemo;

    #[wasm_bindgen(typescript_type = "DecryptedMemo[]")]
    pub type DecryptedMemos;

     #[wasm_bindgen(typescript_type = "StateUpdate")]
    pub type StateUpdate;

    #[wasm_bindgen(typescript_type = "ParseTxsResult")]
    pub type ParseTxsResult;

    #[wasm_bindgen(typescript_type = "ParseTxsColdStorageResult")]
    pub type ParseTxsColdStorageResult;

    #[wasm_bindgen(typescript_type = "TxMemoChunk")]
    pub type TxMemoChunk;

    #[wasm_bindgen(typescript_type = "TxInput")]
    pub type TxInput;

    #[wasm_bindgen(typescript_type = "IAddressComponents")]
    pub type IAddressComponents;
}

#[derive(Serialize, Deserialize, Clone)]
pub struct IndexedAccount {
    pub index: u64,
    pub account: NativeAccount<Fr>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IndexedNote {
    pub index: u64,
    pub note: NativeNote<Fr>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TxInputNodes {
    pub account: IndexedAccount,
    #[serde(rename = "intermediateNullifier")]
    pub intermediate_nullifier: Num<Fr>,   // intermediate nullifier hash
    pub notes: Vec<IndexedNote>,
}

#[derive(Serialize, Deserialize)]
pub struct IndexedTx {
    pub index: u64,
    pub memo: String,
    pub commitment: String,
}
