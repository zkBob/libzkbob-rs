use kvdb::KeyValueDB;
use libzeropool::{
    constants,
    fawkes_crypto::ff_uint::PrimeField,
    fawkes_crypto::{
        core::sizedvec::SizedVec,
        ff_uint::Num,
        ff_uint::{NumRepr, Uint},
        rand::Rng,
    },
    native::{
        account::Account,
        boundednum::BoundedNum,
        cipher,
        key::derive_key_p_d,
        note::Note,
        params::PoolParams,
        tx::{
            make_delta, nullifier, nullifier_intermediate_hash,
            out_commitment_hash, tx_hash, tx_sign,
            TransferPub, TransferSec,
            Tx,
        },
    },
};

use serde::{Deserialize, Serialize};
use std::{convert::TryInto, io::Write, ops::Range};
use thiserror::Error;

use self::state::{State, Transaction};
use crate::{
    address::{format_address, parse_address, AddressParseError, AddressFormat},
    keys::{reduce_sk, Keys},
    random::CustomRng,
    merkle::Hash,
    utils::{keccak256, zero_note, zero_proof},
};

pub mod state;



#[derive(Debug, Error)]
pub enum CreateTxError {
    #[error("Too many outputs: expected {max} max got {got}")]
    TooManyOutputs { max: usize, got: usize },
    #[error("Too few outputs: expected {min} min got {got}")]
    TooFewOutputs { min: usize, got: usize },
    #[error("Could not get merkle proof for leaf {0}")]
    ProofNotFound(u64),
    #[error("Failed to parse address: {0}")]
    AddressParseError(#[from] AddressParseError),
    #[error("Insufficient balance: sum of outputs is greater than sum of inputs: {0} > {1}")]
    InsufficientBalance(String, String),
    #[error("Insufficient energy: available {0}, received {1}")]
    InsufficientEnergy(String, String),
    #[error("Failed to serialize transaction: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct StateFragment<Fr: PrimeField> {
    pub new_leafs: Vec<(u64, Vec<Hash<Fr>>)>,
    pub new_commitments: Vec<(u64, Hash<Fr>)>,
    pub new_accounts: Vec<(u64, Account<Fr>)>,
    pub new_notes: Vec<(u64, Note<Fr>)>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TransactionData<Fr: PrimeField> {
    pub public: TransferPub<Fr>,
    pub secret: TransferSec<Fr>,
    pub ciphertext: Vec<u8>,
    pub memo: Vec<u8>,
    pub commitment_root: Num<Fr>,
    pub out_hashes: SizedVec<Num<Fr>, { constants::OUT + 1 }>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TransactionInputs<Fr: PrimeField> {
    pub account: (u64, Account<Fr>),
    pub intermediate_nullifier: Num<Fr>,   // intermediate nullifier hash
    pub notes: Vec<(u64, Note<Fr>)>,
}

pub type TokenAmount<Fr> = BoundedNum<Fr, { constants::BALANCE_SIZE_BITS }>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TxOutput<Fr: PrimeField> {
    pub to: String,
    pub amount: TokenAmount<Fr>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TxOperator<Fr: PrimeField> {
    pub proxy_address: Vec<u8>,
    pub prover_address: Vec<u8>,
    pub proxy_fee: TokenAmount<Fr>,
    pub prover_fee: TokenAmount<Fr>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExtraItem {
    pub leaf_index: u8, // encrypted items will use associated account\note key
                        // if leaf doesn't exist the item cannot be encrypted
    pub pad_length: u16,  // how many random bytes should be add before the data
    pub need_encrypt: bool,
    pub data: Vec<u8>,  // the rust library doesn't know about the item
                        // content and interpret it just as a byte array
}

impl<Fr: PrimeField> TxOperator<Fr> {
    pub fn serialize(&self, dst: &mut Vec<u8>, is_obsolete_format: bool) {
        if is_obsolete_format {
            let raw_fee: u64 = self.total_fee().try_into().unwrap();
            dst.write_all(&raw_fee.to_be_bytes()).unwrap();
        } else {
            dst.append(&mut self.proxy_address.clone());
            dst.append(&mut self.prover_address.clone());
            let raw_proxy_fee: u64 = self.proxy_fee.to_num().try_into().unwrap();
            let raw_prover_fee: u64 = self.prover_fee.to_num().try_into().unwrap();
            dst.write_all(&raw_proxy_fee.to_be_bytes()).unwrap();
            dst.write_all(&raw_prover_fee.to_be_bytes()).unwrap();
        }
    }

    pub fn total_fee(&self) -> Num<Fr> {
        self.proxy_fee.to_num() + self.prover_fee.to_num()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum TxType<Fr: PrimeField> {
    // operator, extra_data, tx_outputs
    Transfer(TxOperator<Fr>, Vec<ExtraItem>, Vec<TxOutput<Fr>>),
    // operator, extra_data, deposit_amount
    Deposit(TxOperator<Fr>, Vec<ExtraItem>, TokenAmount<Fr>),
    // operator, extra_data, deposit_amount, deadline, holder
    DepositPermittable(
        TxOperator<Fr>,
        Vec<ExtraItem>,
        TokenAmount<Fr>,
        u64,
        Vec<u8>
    ),
    // operator, extra_data, withdraw_amount, to, native_amount, energy_amount
    Withdraw(
        TxOperator<Fr>,
        Vec<ExtraItem>,
        TokenAmount<Fr>,
        Vec<u8>,
        TokenAmount<Fr>,
        TokenAmount<Fr>,
    ),
}

pub struct UserAccount<D: KeyValueDB, P: PoolParams> {
    pub pool_id: u32,
    pub is_obsolete_pool: bool,
    pub keys: Keys<P>,
    pub params: P,
    pub state: State<D, P>,
    pub sign_callback: Option<Box<dyn Fn(&[u8]) -> Vec<u8>>>, // TODO: Find a way to make it async
}

impl<D, P> UserAccount<D, P>
where
    D: KeyValueDB,
    P: PoolParams,
    P::Fr: 'static,
{
    /// Initializes UserAccount with a spending key that has to be an element of the prime field Fs (p = 6554484396890773809930967563523245729705921265872317281365359162392183254199).
    pub fn new(sk: Num<P::Fs>, pool_id: u32, is_obsolete_pool: bool, state: State<D, P>, params: P) -> Self {
        let keys = Keys::derive(sk, &params);

        UserAccount {
            pool_id,
            is_obsolete_pool,
            keys,
            state,
            params,
            sign_callback: None,
        }
    }

    /// Same as constructor but accepts arbitrary data as spending key.
    pub fn from_seed(seed: &[u8], pool_id: u32, is_obsolete_pool: bool, state: State<D, P>, params: P) -> Self {
        let sk = reduce_sk(seed);
        Self::new(sk, pool_id, is_obsolete_pool, state, params)
    }

    fn generate_address_components(
        &self,
    ) -> (
        BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>,
        Num<P::Fr>,
    ) {
        let mut rng = CustomRng;

        let d: BoundedNum<_, { constants::DIVERSIFIER_SIZE_BITS }> = rng.gen();
        let pk_d = derive_key_p_d(d.to_num(), self.keys.eta, &self.params);
        (d, pk_d.x)
    }

    /// Generates a new private address for the current pool
    pub fn generate_address(&self) -> String {
        let (d, p_d) = self.generate_address_components();

        format_address::<P>(d, p_d, Some(self.pool_id))
    }

    /// Generates a new private generic address (for all pools)
    pub fn generate_universal_address(&self) -> String {
        let (d, p_d) = self.generate_address_components();

        format_address::<P>(d, p_d, None)
    }

    pub fn generate_address_from_components(
        &self,
        d: BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>,
        p_d: Num<P::Fr>
    ) -> String {
        format_address::<P>(d, p_d, Some(self.pool_id))
    }

    pub fn generate_universal_address_from_components(
        &self,
        d: BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>,
        p_d: Num<P::Fr>
    ) -> String {
        format_address::<P>(d, p_d, None)
    }

    pub fn gen_address_for_seed(&self, seed: &[u8]) -> String {
        self.gen_address_for_seed_and_pool_id(seed, Some(self.pool_id))
    }

    pub fn gen_universal_address_for_seed(&self, seed: &[u8]) -> String {
        self.gen_address_for_seed_and_pool_id(seed, None)
    }

    fn gen_address_for_seed_and_pool_id(&self, seed: &[u8], pool_id: Option<u32>) -> String {
        let mut rng = CustomRng;

        let sk = reduce_sk(seed);
        let keys = Keys::derive(sk, &self.params);
        let d: BoundedNum<_, { constants::DIVERSIFIER_SIZE_BITS }> = rng.gen();
        let pk_d = derive_key_p_d(d.to_num(), keys.eta, &self.params);

        format_address::<P>(d, pk_d.x, pool_id)
    }

    pub fn validate_address(&self, address: &str) -> bool {
        match parse_address(address, &self.params, self.pool_id) {
            Ok((_, _, format)) => format == AddressFormat::PoolSpecific,
            Err(_) => false,
        }
    }

    pub fn validate_universal_address(&self, address: &str) -> bool {
        match parse_address(address, &self.params, self.pool_id) {
            Ok((_, _, format)) => format == AddressFormat::Generic,
            Err(_) => false,
        }
    }

    pub fn is_own_address(&self, address: &str) -> bool {
        match parse_address::<P>(address, &self.params, self.pool_id) {
            Ok((d, p_d, _)) => {
                self.is_derived_from_our_sk(d, p_d)
            },
            Err(_) => false
        }
    }

    pub fn is_derived_from_our_sk(&self, d: BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>, p_d: Num<P::Fr>) -> bool {
        derive_key_p_d(d.to_num(), self.keys.eta, &self.params).x == p_d
    }

    /// Attempts to decrypt notes.
    pub fn decrypt_notes(&self, data: Vec<u8>) -> Vec<Option<Note<P::Fr>>> {
        cipher::decrypt_in(self.keys.eta, &data, &self.params)
    }

    /// Attempts to decrypt account and notes.
    pub fn decrypt_pair(&self, data: Vec<u8>) -> Option<(Account<P::Fr>, Vec<Note<P::Fr>>)> {
        cipher::decrypt_out(self.keys.eta, &self.keys.kappa, &data, &self.params)
    }

    pub fn initial_account(&self) -> Account<P::Fr> {
        // Initial account should have d = pool_id to protect from reply attacks
        let d = Num::<P::Fr>::from_uint(NumRepr(Uint::from_u64(self.pool_id as u64))).unwrap();
        let p_d = derive_key_p_d(d, self.keys.eta, &self.params).x;
        Account {
            d: BoundedNum::new(d),
            p_d,
            i: BoundedNum::new(Num::ZERO),
            b: BoundedNum::new(Num::ZERO),
            e: BoundedNum::new(Num::ZERO),
        }
    }

    /// Constructs a transaction.
    pub fn create_tx(
        &self,
        tx: TxType<P::Fr>,
        delta_index: Option<u64>,
        extra_state: Option<StateFragment<P::Fr>>
    ) -> Result<TransactionData<P::Fr>, CreateTxError> {
        let mut rng = CustomRng;
        let keys = self.keys.clone();
        let state = &self.state;

        let extra_state = extra_state.unwrap_or(
            StateFragment {
                new_leafs: [].to_vec(),
                new_commitments: [].to_vec(),
                new_accounts: [].to_vec(),
                new_notes: [].to_vec(),
            }
        );

        // initial input account (from optimistic state)
        let (in_account_optimistic_index, in_account_optimistic) = {
            let last_acc = extra_state.new_accounts.last();
            match last_acc {
                Some(last_acc) => (Some(last_acc.0), Some(last_acc.1)),
                _ => (None, None),
            }
        };

        // initial input account (from non-optimistic state)
        let in_account = in_account_optimistic.unwrap_or_else(|| {
            state.latest_account.unwrap_or_else(|| self.initial_account())
        });

        let tree = &self.state.tree;

        let in_account_index = in_account_optimistic_index.or(state.latest_account_index);

        // initial usable note index
        let next_usable_index = state.earliest_usable_index_optimistic(&extra_state.new_accounts, &extra_state.new_notes);

        let latest_note_index_optimistic = extra_state.new_notes
            .last()
            .map(|indexed_note| indexed_note.0)
            .unwrap_or(state.latest_note_index);

        // Should be provided by relayer together with note proofs, but as a fallback
        // take the next index of the tree (optimistic part included).
        let delta_index = Num::from(delta_index.unwrap_or_else( || {
            let next_by_optimistic_leaf = extra_state.new_leafs
                .last()
                .map(|leafs| {
                    (((leafs.0 + (leafs.1.len() as u64) - 1) >> constants::OUTPLUSONELOG) + 1) << constants::OUTPLUSONELOG
                });
            let next_by_optimistic_commitment = extra_state.new_commitments
                .last()
                .map(|commitment| {
                    ((commitment.0  >> constants::OUTPLUSONELOG) + 1) << constants::OUTPLUSONELOG
                });
            next_by_optimistic_leaf
                .into_iter()
                .chain(next_by_optimistic_commitment)
                .max()
                .unwrap_or_else(|| self.state.tree.next_index())
        }));

        let (fee, tx_data, _user_data) = {
            let mut tx_data: Vec<u8> = vec![];
            match &tx {
                TxType::Deposit(operator, user_data, _) => {
                    operator.serialize(&mut tx_data, self.is_obsolete_pool);

                    (operator.total_fee(), tx_data, user_data)
                }
                TxType::DepositPermittable(operator, user_data, _, deadline, holder) => {
                    operator.serialize(&mut tx_data, self.is_obsolete_pool);
                    tx_data.write_all(&deadline.to_be_bytes()).unwrap();
                    tx_data.append(&mut holder.clone());
                    
                    (operator.total_fee(), tx_data, user_data)
                }
                TxType::Transfer(operator, user_data, _) => {
                    operator.serialize(&mut tx_data, self.is_obsolete_pool);

                    (operator.total_fee(), tx_data, user_data)
                }
                TxType::Withdraw(operator, user_data, _, reciever, native_amount, _) => {
                    operator.serialize(&mut tx_data, self.is_obsolete_pool);
                    let raw_native_amount: u64 = native_amount.to_num().try_into().unwrap();
                    tx_data.write_all(&raw_native_amount.to_be_bytes()).unwrap();
                    tx_data.append(&mut reciever.clone());

                    (operator.total_fee(), tx_data, user_data)
                }
            }
        };

        // Optimistic available notes
        let optimistic_available_notes = extra_state.new_notes
            .into_iter()
            .filter(|indexed_note| indexed_note.0 >= next_usable_index);

        // Fetch constants::IN usable notes from state
        let in_notes_original: Vec<(u64, Note<P::Fr>)> = state
            .txs
            .iter_slice(next_usable_index..=state.latest_note_index)
            .filter_map(|(index, tx)| match tx {
                Transaction::Note(note) => Some((index, note)),
                _ => None,
            })
            .chain(optimistic_available_notes)
            .take(constants::IN)
            .collect();
        
        let spend_interval_index = in_notes_original
            .last()
            .map(|(index, _)| *index + 1)
            .unwrap_or(if latest_note_index_optimistic > 0 { latest_note_index_optimistic + 1 } else { 0 });

        // Calculate total balance (account + constants::IN notes).
        let mut input_value = in_account.b.to_num();
        for (_index, note) in &in_notes_original {
            input_value += note.b.to_num();
        }

        let mut output_value = Num::ZERO;

        let (num_real_out_notes, out_notes): (_, SizedVec<_, { constants::OUT }>) =
            if let TxType::Transfer(_, _, outputs) = &tx {
                if outputs.len() > constants::OUT {
                    return Err(CreateTxError::TooManyOutputs {
                        max: constants::OUT,
                        got: outputs.len(),
                    });
                }

                let out_notes = outputs
                    .iter()
                    .map(|dest| {
                        let (to_d, to_p_d, _) = parse_address::<P>(&dest.to, &self.params, self.pool_id)?;
                        output_value += dest.amount.to_num();
                        Ok(Note {
                            d: to_d,
                            p_d: to_p_d,
                            b: dest.amount,
                            t: rng.gen(),
                        })
                    })
                    // fill out remaining output notes with zeroes
                    .chain((0..).map(|_| Ok(zero_note())))
                    .take(constants::OUT)
                    .collect::<Result<SizedVec<_, { constants::OUT }>, CreateTxError>>()?;

                (outputs.len(), out_notes)
            } else {
                (0, (0..).map(|_| zero_note()).take(constants::OUT).collect())
            };

        let mut delta_value = -fee;
        // By default all account energy will be withdrawn on withdraw tx
        let mut delta_energy = Num::ZERO;

        let in_account_pos = in_account_index.unwrap_or(0);

        let mut input_energy = in_account.e.to_num();
        input_energy += in_account.b.to_num() * (delta_index - Num::from(in_account_pos));

        for (note_index, note) in &in_notes_original {
            input_energy += note.b.to_num() * (delta_index - Num::from(*note_index));
        }
        let new_balance = match &tx {
            TxType::Transfer(_, _, _) => {
                if input_value.to_uint() >= (output_value + fee).to_uint() {
                    input_value - output_value - fee
                } else {
                    return Err(CreateTxError::InsufficientBalance(
                        (output_value + fee).to_string(),
                        input_value.to_string(),
                    ));
                }
            }
            TxType::Withdraw(_, _, amount, _, _, energy) => {
                let amount = amount.to_num();
                let energy = energy.to_num();

                if energy.to_uint() > input_energy.to_uint() {
                    return Err(CreateTxError::InsufficientEnergy(
                        input_energy.to_string(),
                        energy.to_string(),
                    ));
                }

                delta_energy -= energy;
                delta_value -= amount;

                if input_value.to_uint() >= amount.to_uint() {
                    input_value + delta_value
                } else {
                    return Err(CreateTxError::InsufficientBalance(
                        delta_value.to_string(),
                        input_value.to_string(),
                    ));
                }
            }
            TxType::Deposit(_, _, amount) | TxType::DepositPermittable(_, _, amount, _, _) => {
                delta_value += amount.to_num();
                input_value + delta_value
            }
        };

        let (d, p_d) = self.generate_address_components();
        let out_account = Account {
            d,
            p_d,
            i: BoundedNum::new(Num::from(spend_interval_index)),
            b: BoundedNum::new(new_balance),
            e: BoundedNum::new(delta_energy + input_energy),
        };

        let in_account_hash = in_account.hash(&self.params);
        let nullifier = nullifier(
            in_account_hash,
            keys.eta,
            in_account_pos.into(),
            &self.params,
        );

        let ciphertext = {
            let entropy: [u8; 32] = rng.gen();

            // No need to include all the zero notes in the encrypted transaction
            let out_notes = &out_notes[0..num_real_out_notes];

            match self.is_obsolete_pool {
                true => cipher::_encrypt_old(&entropy, keys.eta, out_account, out_notes, &self.params), // ECDH scheme
                false => cipher::encrypt(&entropy, &keys.kappa, out_account, out_notes, &self.params),  // symmetric scheme
            }
        };

        // Hash input account + notes filling remaining space with non-hashed zeroes
        let owned_zero_notes = (0..).map(|_| {
            let d: BoundedNum<_, { constants::DIVERSIFIER_SIZE_BITS }> = rng.gen();
            let p_d = derive_key_p_d::<P, P::Fr>(d.to_num(), keys.eta, &self.params).x;
            Note {
                d,
                p_d,
                b: BoundedNum::new(Num::ZERO),
                t: rng.gen(),
            }
        });
        let in_notes: SizedVec<Note<P::Fr>, { constants::IN }> = in_notes_original
            .iter()
            .map(|(_, note)| note)
            .cloned()
            .chain(owned_zero_notes)
            .take(constants::IN)
            .collect();
        let in_note_hashes = in_notes.iter().map(|note| note.hash(&self.params));
        let input_hashes: SizedVec<_, { constants::IN + 1 }> = [in_account_hash]
            .iter()
            .copied()
            .chain(in_note_hashes)
            .collect();

        // Same with output
        let out_account_hash = out_account.hash(&self.params);
        let out_note_hashes = out_notes.iter().map(|n| n.hash(&self.params));
        let out_hashes: SizedVec<Num<P::Fr>, { constants::OUT + 1 }> = [out_account_hash]
            .iter()
            .copied()
            .chain(out_note_hashes)
            .collect();

        let out_commit = out_commitment_hash(out_hashes.as_slice(), &self.params);
        let tx_hash = tx_hash(input_hashes.as_slice(), out_commit, &self.params);

        let delta = make_delta::<P::Fr>(
            delta_value,
            delta_energy,
            delta_index,
            Num::<P::Fr>::from_uint(NumRepr(Uint::from_u64(self.pool_id as u64))).unwrap(),
        );

        // calculate virtual subtree from the optimistic state
        let new_leafs = extra_state.new_leafs.iter().cloned();
        let new_commitments = extra_state.new_commitments.iter().cloned();
        let (mut virtual_nodes, update_boundaries) = tree.get_virtual_subtree(new_leafs, new_commitments);

        let root: Num<P::Fr> = tree.get_root_optimistic(&mut virtual_nodes, &update_boundaries);

        // TODO: prepare (encrypt) extra data

        // memo = tx_specific_data, ciphertext, extra_data
        let mut memo_data = {
            let tx_data_size = tx_data.len();
            let ciphertext_size_size = if self.is_obsolete_pool { 0 } else { 2 };
            let ciphertext_size = ciphertext.len();
            let user_data_size = 0; //user_data.len();
            Vec::with_capacity(tx_data_size + ciphertext_size_size + ciphertext_size + user_data_size)
        };

        #[allow(clippy::redundant_clone)]
        memo_data.append(&mut tx_data.clone());
        if !self.is_obsolete_pool {
            // add message size for new memo format
            memo_data.extend((ciphertext.len() as u16).to_be_bytes());
        }
        memo_data.extend(&ciphertext);
        // TODO: append extra data here!

        let memo_hash = keccak256(&memo_data);
        let memo = Num::from_uint_reduced(NumRepr(Uint::from_big_endian(&memo_hash)));

        let public = TransferPub::<P::Fr> {
            root,
            nullifier,
            out_commit,
            delta,
            memo,
        };

        let tx = Tx {
            input: (in_account, in_notes),
            output: (out_account, out_notes),
        };

        let (eddsa_s, eddsa_r) = tx_sign(keys.sk, tx_hash, &self.params);

        let account_proof = in_account_index.map_or_else(
            || Ok(zero_proof()),
            |i| {
                tree.get_proof_optimistic_index(i, &mut virtual_nodes, &update_boundaries)
                    .ok_or(CreateTxError::ProofNotFound(i))
            },
        )?;
        let note_proofs = in_notes_original
            .iter()
            .copied()
            .map(|(index, _note)| {
                tree.get_proof_optimistic_index(index, &mut virtual_nodes, &update_boundaries)
                    .ok_or(CreateTxError::ProofNotFound(index))
            })
            .chain((0..).map(|_| Ok(zero_proof())))
            .take(constants::IN)
            .collect::<Result<_, _>>()?;

        
        let secret = TransferSec::<P::Fr> {
            tx,
            in_proof: (account_proof, note_proofs),
            eddsa_s: eddsa_s.to_other().unwrap(),
            eddsa_r,
            eddsa_a: keys.a,
        };

        Ok(TransactionData {
            public,
            secret,
            ciphertext,
            memo: memo_data,
            commitment_root: out_commit,
            out_hashes,
        })
    }

    pub fn get_tx_input(&self, index: u64) -> Option<TransactionInputs<P::Fr>> {
        let account = match self.state.get_account(index) {
            Some(acc) => acc,
            _ => return None,
        };

        let input_acc = self.state.get_previous_account(index).unwrap_or_else(|| (0, self.initial_account()));
        let note_lower_bound = input_acc.1.i.to_num().try_into().unwrap();
        let note_upper_bound = account.i.to_num().try_into().unwrap();
        let notes_range: Range<u64> = note_lower_bound..note_upper_bound;
        let input_notes = self.state.get_notes_in_range(notes_range);

        let params = &self.params;
        let inh = nullifier_intermediate_hash(input_acc.1.hash(params), self.keys.eta, index.into(), params);

        Some(TransactionInputs {
            account: input_acc,
            intermediate_nullifier: inh,
            notes: input_notes,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use libzeropool::POOL_PARAMS;
    use crate::random::CustomRng;

    #[test]
    fn test_create_tx_deposit_zero() {
        let state = State::init_test(POOL_PARAMS.clone());
        let acc = UserAccount::new(Num::ZERO, 0, false, state, POOL_PARAMS.clone());

        let op = TxOperator {
            proxy_address: vec![],
            prover_address: vec![],
            proxy_fee: BoundedNum::ZERO,
            prover_fee: BoundedNum::ZERO,
        };

        acc.create_tx(
            TxType::Deposit(
                op,
                vec![],
                BoundedNum::ZERO,
            ),
            None,
            None,
        )
        .unwrap();
    }

    #[test]
    fn test_create_tx_deposit_one() {
        let state = State::init_test(POOL_PARAMS.clone());
        let acc = UserAccount::new(Num::ZERO, 0, false, state, POOL_PARAMS.clone());

        let op = TxOperator {
            proxy_address: vec![],
            prover_address: vec![],
            proxy_fee: BoundedNum::ZERO,
            prover_fee: BoundedNum::ONE,
        };

        acc.create_tx(
            TxType::Deposit(
                op,
                vec![],
                BoundedNum::new(Num::ONE),
            ),
            None,
            None,
        )
        .unwrap();
    }

    // It's ok to transfer 0 while balance = 0
    #[test]
    fn test_create_tx_transfer_zero() {
        let state = State::init_test(POOL_PARAMS.clone());
        let acc = UserAccount::new(Num::ZERO, 0, false, state, POOL_PARAMS.clone());

        let addr = acc.generate_address();

        let out = TxOutput {
            to: addr,
            amount: BoundedNum::new(Num::ZERO),
        };

        let op = TxOperator {
            proxy_address: vec![],
            prover_address: vec![],
            proxy_fee: BoundedNum::ZERO,
            prover_fee: BoundedNum::ZERO,
        };

        acc.create_tx(
            TxType::Transfer(op, vec![], vec![out]),
            None,
            None,
        )
        .unwrap();
    }

    #[test]
    #[should_panic]
    fn test_create_tx_transfer_one_no_balance() {
        let state = State::init_test(POOL_PARAMS.clone());
        let acc = UserAccount::new(Num::ZERO, 0, false, state, POOL_PARAMS.clone());

        let addr = acc.generate_address();

        let out = TxOutput {
            to: addr,
            amount: BoundedNum::new(Num::ONE),
        };

        let op = TxOperator {
            proxy_address: vec![],
            prover_address: vec![],
            proxy_fee: BoundedNum::ZERO,
            prover_fee: BoundedNum::ZERO,
        };

        acc.create_tx(
            TxType::Transfer(op, vec![], vec![out]),
            None,
            None,
        )
        .unwrap();
    }

    #[test]
    fn test_user_account_is_own_address() {
        let acc_1 = UserAccount::new(
            Num::ZERO,
            0xffff02,
            false, 
            State::init_test(POOL_PARAMS.clone()),
            POOL_PARAMS.clone(),
        );
        let acc_2 = UserAccount::new(
            Num::ONE,
            0xffff02,
            false, 
            State::init_test(POOL_PARAMS.clone()),
            POOL_PARAMS.clone(),
        );

        let address_1 = acc_1.generate_address();
        let address_2 = acc_2.generate_address();

        assert!(acc_1.is_own_address(&address_1));
        assert!(acc_2.is_own_address(&address_2));

        assert!(!acc_1.is_own_address(&address_2));
        assert!(!acc_2.is_own_address(&address_1));
    }

    #[test]
    fn test_tx_inputs() {
        let params = POOL_PARAMS.clone();
        let mut rng = CustomRng;
        let state = State::init_test(POOL_PARAMS.clone());
        let mut user_account = UserAccount::new(
            Num::ZERO,
            1,
            false, 
            state,
            POOL_PARAMS.clone()
        );

        let mut acc0 = Account::sample(&mut rng, &params);
        acc0.i = BoundedNum::new(Num::from_str("0").unwrap());
        let mut acc1 = Account::sample(&mut rng, &params);
        acc1.i = BoundedNum::new(Num::from_str("51").unwrap());
        let mut acc2 = Account::sample(&mut rng, &params);
        acc2.i = BoundedNum::new(Num::from_str("259").unwrap());

        let note0 = (50, Note::sample(&mut rng, &params));
        let note1 = (257, Note::sample(&mut rng, &params));
        let note2 = (258, Note::sample(&mut rng, &params));
        let note3 = (259, Note::sample(&mut rng, &params));
        let note4 = (300, Note::sample(&mut rng, &params));
        let note5 = (666, Note::sample(&mut rng, &params));

        user_account.state.add_account(0, acc0);
        user_account.state.add_account(128, acc1);
        user_account.state.add_note(note0.0, note0.1);
        user_account.state.add_note(note1.0, note1.1);
        user_account.state.add_note(note2.0, note2.1);
        user_account.state.add_note(note3.0, note3.1);
        user_account.state.add_note(note4.0, note4.1);
        user_account.state.add_note(note5.0, note5.1);
        user_account.state.add_account(1024, acc2);

        (0..10).into_iter().for_each(|idx| {
            user_account.state.add_note(1024 + idx + 1, Note::sample(&mut rng, &params))
        });

        let inputs0 = user_account.get_tx_input(0).unwrap();
        assert!(inputs0.account.1 == user_account.initial_account());
        assert_eq!(inputs0.notes.len(), 0);

        let inputs1 = user_account.get_tx_input(128).unwrap();
        assert!(inputs1.account.1 == acc0);
        assert_eq!(inputs1.notes.len(), 1);
        assert!(inputs1.notes.contains(&note0));

        let inputs2 = user_account.get_tx_input(1024).unwrap();
        assert!(inputs2.account.1 == acc1);
        assert_eq!(inputs2.notes.len(), 2);
        assert!(inputs2.notes.contains(&note1));
        assert!(inputs2.notes.contains(&note2));

    }

    #[test]
    fn test_chain_specific_addresses() {
        let acc_polygon = UserAccount::new(Num::ZERO, 0, false, State::init_test(POOL_PARAMS.clone()), POOL_PARAMS.clone());
        let acc_sepolia = UserAccount::new(Num::ZERO, 0, false, State::init_test(POOL_PARAMS.clone()), POOL_PARAMS.clone());
        let acc_optimism = UserAccount::new(Num::ZERO, 1, false, State::init_test(POOL_PARAMS.clone()), POOL_PARAMS.clone());
        let acc_optimism_eth = UserAccount::new(Num::ZERO, 2, false, State::init_test(POOL_PARAMS.clone()), POOL_PARAMS.clone());

        assert!(acc_polygon.validate_universal_address("PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kxBwa"));   // generic without a prefix
        assert!(acc_polygon.validate_universal_address("zkbob:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kxBwa")); // generic
        assert!(acc_polygon.validate_address("zkbob_polygon:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kRF7i"));
        assert!(!acc_polygon.validate_address("zkbob_optimism:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5vHs5L"));
        assert!(!acc_polygon.validate_address("zkbob_polygon:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5vHs5L"));

        assert!(acc_sepolia.validate_universal_address("PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kxBwa"));
        assert!(acc_sepolia.validate_universal_address("zkbob:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kxBwa"));
        assert!(acc_sepolia.validate_address("zkbob_polygon:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kRF7i")); // true due to the same pool_id
        assert!(!acc_sepolia.validate_address("zkbob_optimism:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5vHs5L"));
        assert!(!acc_sepolia.validate_address("zkbob_polygon:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5vHs5L"));
        
        assert!(acc_optimism.validate_universal_address("PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kxBwa"));
        assert!(acc_optimism.validate_universal_address("zkbob:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kxBwa"));
        assert!(!acc_optimism.validate_address("zkbob_polygon:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kRF7i"));
        assert!(acc_optimism.validate_address("zkbob_optimism:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5vHs5L"));
        assert!(acc_optimism.validate_address("zkbob_polygon:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5vHs5L")); // the lib cannot distinguish different address prefixes
        assert!(!acc_optimism.validate_address("zkbob_optimism:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kRF7i"));
        assert!(!acc_optimism.validate_address("zkbob_optimism:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kR*&**7i"));
        assert!(acc_optimism.validate_address("zkbob_zkbober:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5vHs5L"));
        assert!(acc_optimism.validate_address("zkbob:optimism:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5vHs5L"));
        assert!(!acc_optimism.validate_universal_address("zkbob:"));
        assert!(!acc_optimism.validate_address(":"));
        assert!(!acc_optimism.validate_address(""));

        assert!(acc_optimism_eth.validate_universal_address("PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kxBwa"));
        assert!(acc_optimism_eth.validate_universal_address("zkbob:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kxBwa"));
        assert!(acc_optimism_eth.validate_address("zkbob_optimism_eth:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse1j9diw"));
        assert!(!acc_optimism_eth.validate_address("zkbob_polygon:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kRF7i"));
        assert!(!acc_optimism_eth.validate_address("zkbob_optimism:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5vHs5L"));
        assert!(!acc_optimism_eth.validate_address("zkbob_optimism_eth:PtfsqyJhA2yvmLtXBm55pkvFDX6XZrRMaib9F1GvwzmU8U4witUf8Jyse5kRF7i"));
    }   

    #[test]
    fn test_chain_specific_address_ownable() {
        let accs = [
            UserAccount::new(Num::ZERO, 0, false, State::init_test(POOL_PARAMS.clone()), POOL_PARAMS.clone()),
            UserAccount::new(Num::ZERO, 1, false, State::init_test(POOL_PARAMS.clone()), POOL_PARAMS.clone()),
            UserAccount::new(Num::ZERO, 2, false, State::init_test(POOL_PARAMS.clone()), POOL_PARAMS.clone()),
            UserAccount::new(Num::ZERO, 0xffff02, false, State::init_test(POOL_PARAMS.clone()), POOL_PARAMS.clone()),
            UserAccount::new(Num::ZERO, 0xffff03, false, State::init_test(POOL_PARAMS.clone()), POOL_PARAMS.clone()),
        ];
        let acc2 = UserAccount::new(Num::ONE, 1, false, State::init_test(POOL_PARAMS.clone()), POOL_PARAMS.clone());
        let pool_addresses: Vec<String> = accs.iter().map(|acc| acc.generate_address()).collect();
        let universal_addresses: Vec<String> = accs.iter().map(|acc| acc.generate_universal_address()).collect();

        accs.iter().enumerate().for_each(|(acc_idx, acc)| {
            pool_addresses.iter().enumerate().for_each(|(addr_idx, addr)| {
                if addr_idx == acc_idx {
                    assert!(acc.is_own_address(&addr));
                } else {
                    assert!(!acc.is_own_address(&addr));
                }
                assert!(!acc2.is_own_address(&addr))
            });

            universal_addresses.iter().for_each(|addr| {
                assert!(acc.is_own_address(&addr));
                assert!(!acc2.is_own_address(&addr))
            });
        });
    }
}
