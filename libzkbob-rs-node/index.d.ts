export namespace Constants {
    export const HEIGHT: number;
    export const IN: number;
    export const OUTLOG: number;
    export const OUT: number;
    export const DELEGATED_DEPOSITS_NUM: number;
}

declare class MerkleTree {
    constructor(path: string);

    getRoot(): string;
    getNextIndex(): number;
    getNode(height: number, index: number): string;
    addHash(index: number, hash: Buffer): void;
    addCommitment(index: number, hash: Buffer): void;
    appendHash(hash: Buffer): number;
    getProof(index: number): MerkleProof;
    getCommitmentProof(index: number): MerkleProof;
    getAllNodes(): any;
    getVirtualNode(
        height: number,
        index: number,
        virtual_nodes: any,
        new_hashes_left_index: number,
        new_hashes_right_index: number,
    ): any;
    rollback(index: number): number;
    wipe(): void;
    getLeftSiblings(index: number): string[];
    getLastStableIndex(): number;
    setLastStableIndex(index: number): void;
    getRootAt(index: number): string;
}

declare class TxStorage {
    constructor(path: string);
    add(index: number, data: Buffer): void;
    get(index: number): Buffer | null;
    delete(index: number): void;
    count(): number;
}

export interface TransferPub {
    root: string;
    nullifier: string;
    out_commit: string;
    delta: string;
    memo: string;
}

export interface Note {
    d: string;
    p_d: string;
    b: string;
    t: string;
}

export interface Account {
    eta: string;
    i: string;
    b: string;
    e: string;
    t: string;
}

export interface Tx {
    input: { account: Account; notes: Array<Note> };
    output: { account: Account; notes: Array<Note> };
}

export interface TransferSec {
    tx: Tx;
    in_proof: { account: MerkleProof; notes: Array<MerkleProof> };
    eddsa_s: string;
    eddsa_r: string;
    eddsa_a: string;
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

export interface MerkleProof {
    sibling: string[];
    path: boolean[];
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

declare class Params {
    static fromBinary(data: Buffer, precompute: boolean): Params;
    static fromFile(path: string, precompute: boolean): Params;
}

declare class Proof {
    inputs: Array<string>;
    proof: SnarkProof;

    static tx(params: Params, tr_pub: TransferPub, tr_sec: TransferSec): Proof;
    static tree(params: Params, tr_pub: TreePub, tr_sec: TreeSec): Proof;
    static delegatedDeposit(params: Params, tr_pub: DelegatedDepositBatchPub, tr_sec: DelegatedDepositBatchSec): Proof;
    static txAsync(params: Params, tr_pub: TransferPub, tr_sec: TransferSec): Promise<Proof>;
    static treeAsync(params: Params, tr_pub: TreePub, tr_sec: TreeSec): Promise<Proof>;
    static delegatedDepositAsync(params: Params, tr_pub: DelegatedDepositBatchPub, tr_sec: DelegatedDepositBatchSec): Promise<Proof>;
    static verify(vk: VK, proof: SnarkProof, inputs: Array<string>): boolean;
}

declare class Helpers {
    static outCommitmentHash(hashes: Array<Buffer>): string
    static parseDelta(delta: string): { v: string, e: string, index: string, poolId: string }
    static numToStr(num: Buffer): string
    static strToNum(str: string): Buffer
    static isInPrimeSubgroup(num: Buffer): boolean
}

declare class Keys {
    public sk: string;
    public a: string;
    public eta: string;

    static derive(sk: string): Keys;
}

declare class TransactionData {
    public: TransferPub;
    secret: TransferSec;
    ciphertext: Buffer;
    memo: Buffer;
    commitment_root: string;
    out_hashes: string[];
}

interface FullDelegatedDeposit {
    id: string | number;
    owner: string | number;
    receiver_d: string | number;
    receiver_p: string | number;
    denominated_amount: string | number;
    denominated_fee: string | number;
    expired: string | number;
}

interface MemoDelegatedDeposit {
    id: string | number;
    receiver_d: string | number;
    receiver_p: string | number;
    denominated_amount: string | number;
}

interface DelegatedDeposit {
    d: string;
    p_d: string;
    b: string;
}

interface DelegatedDepositBatchPub {
    keccak_sum: string;
}

interface DelegatedDepositBatchSec {
    deposits: DelegatedDeposit[];
}

declare class DelegatedDepositsData {
    public: DelegatedDepositBatchPub;
    secret: DelegatedDepositBatchSec;
    memo: Buffer;
    out_commitment_hash: string;

    static create(
        deposits: MemoDelegatedDeposit[],
    ): Promise<DelegatedDepositsData>;
}

declare function delegatedDepositsToCommitment(
    deposits: MemoDelegatedDeposit[],
): string;

