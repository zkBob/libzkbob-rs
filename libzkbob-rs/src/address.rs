use std::convert::TryInto;

const POOL_ID_BITS: usize = 24;
const POOL_ID_BYTES: usize = POOL_ID_BITS >> 3;

use crate::utils::keccak256;
use libzeropool::{
    constants,
    fawkes_crypto::{
        borsh::{BorshDeserialize, BorshSerialize},
        ff_uint::Num,
        native::ecc::EdwardsPoint,
    },
    native::boundednum::BoundedNum,
    native::params::PoolParams,
};
use thiserror::Error;

const ADDR_LEN: usize = 46;

#[derive(Error, Debug)]
pub enum AddressParseError {
    #[error("Invalid format")]
    InvalidFormat,
    #[error("Invalid prefix {0}")]
    InvalidPrefix(String),
    #[error("Invalid checksum")]
    InvalidChecksum,
    #[error("Pd does not belongs prime subgroup")]
    InvalidNumber,
    #[error("Decode error: {0}")]
    Base58DecodeError(#[from] bs58::decode::Error),
    #[error("Deserialization error: {0}")]
    DeserializationError(#[from] std::io::Error),
}

#[derive(PartialEq)]
pub enum AddressFormat {
    PoolSpecific,
    Generic,
}

impl AddressFormat {
    pub fn name(&self) -> &str {
        match self {
            AddressFormat::PoolSpecific => "pool",
            AddressFormat::Generic => "generic",
        }
    }
}

pub fn parse_address<P: PoolParams>(
    address: &str,
    params: &P,
    pool_id: u32,   // current pool id
) -> Result<
    (
        BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>, // d
        Num<P::Fr>, // p_d
        AddressFormat,
    ),
    AddressParseError,
>{
    let (d, p_d, _, format, _) = parse_address_ext(address, params, pool_id)?;
    Ok((d, p_d, format))
}

pub fn parse_address_ext<P: PoolParams>(
    address: &str,
    params: &P,
    pool_id: u32,
) -> Result<
    (
        BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>, // d
        Num<P::Fr>, // p_d
        Option<u32>,   // None for generic addresses (otherwse pool id)
        AddressFormat,
        [u8; 4],    // checksum
    ),
    AddressParseError,
>{
    // ignoring any prefixes, just try to validate checksum
    let addr_components: Vec<&str> = address.split(':').filter(|s| !s.is_empty()).collect();  
    match addr_components.last() {
        Some(addr) => {
            // parse address
            let (d,
                p_d,
                addr_hash,
                checksum) = parse_address_raw(addr, params)?;


            if addr_hash[0..=3] != checksum {
                // calcing checksum [pool-specific format]
                let mut hash_src: [u8; POOL_ID_BYTES + 32] = [0; POOL_ID_BYTES + 32];
                pool_id_to_bytes_be::<P>(pool_id).serialize(& mut &mut hash_src[0..POOL_ID_BYTES]).unwrap();
                hash_src[POOL_ID_BYTES..POOL_ID_BYTES + 32].clone_from_slice(&addr_hash);

                if keccak256(&hash_src)[0..=3] == checksum {
                    Ok((d, p_d, Some(pool_id), AddressFormat::PoolSpecific, checksum))
                } else {
                    Err(AddressParseError::InvalidChecksum)
                }
            } else {
                // generic format
                Ok((d, p_d, None, AddressFormat::Generic, checksum))
            }

        },
        None => Err(AddressParseError::InvalidFormat),
    }
    
}

fn parse_address_raw<P: PoolParams>(
    raw_address: &str,
    params: &P,
) -> Result<
    (
        BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>, // d
        Num<P::Fr>, // p_d
        [u8; 32],   // keccak256(d ++ p_d)
        [u8; 4],    // checksum (not checked, just extracted)
    ),
    AddressParseError,
>{
    let mut bytes = [0; ADDR_LEN];
    bs58::decode(raw_address).into(&mut bytes)?;

    let d = BoundedNum::try_from_slice(&bytes[0..10])?;
    let p_d = Num::try_from_slice(&bytes[10..42])?;
    let checksum = bytes[42..=45].try_into().unwrap();

    match EdwardsPoint::subgroup_decompress(p_d, params.jubjub()) {
        Some(_) => Ok((d, p_d, keccak256(&bytes[0..=41]), checksum)),
        None => Err(AddressParseError::InvalidNumber)
    }
}

// generates shielded address in format "base58(d ++ p_d ++ checksum)"
// pool prefix doesn't append here
// both address types (pool-specific\generic) can generated here
pub fn format_address<P: PoolParams>(
    d: BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>,
    p_d: Num<P::Fr>,
    pool_id: Option<u32>, // set pool_id to None to generate universal address for all pools
) -> String {
    let mut buf: [u8; ADDR_LEN] = [0; ADDR_LEN];

    d.serialize(&mut &mut buf[0..10]).unwrap();
    p_d.serialize(&mut &mut buf[10..42]).unwrap();

    // there are two ways for checksum calculation
    let checksum_hash = match pool_id {
        // pool-specific format
        Some(pool_id) => {
            let mut hash_src: [u8; POOL_ID_BYTES + 32] = [0; POOL_ID_BYTES + 32];
            pool_id_to_bytes_be::<P>(pool_id).serialize(& mut &mut hash_src[0..POOL_ID_BYTES]).unwrap();
            hash_src[POOL_ID_BYTES..POOL_ID_BYTES + 32].clone_from_slice(&keccak256(&buf[0..42]));
            keccak256(&hash_src)
        },
        // generic format (for all pools, when pool_id isn't specified)
        None => keccak256(&buf[0..42]),
    };
    buf[42..ADDR_LEN].clone_from_slice(&checksum_hash[0..4]);

    bs58::encode(buf).into_string()
}

fn pool_id_to_bytes_be<P: PoolParams>(pool_id: u32) -> [u8; POOL_ID_BYTES] {
    // preparing pool id for checksum validation
    pool_id.to_be_bytes()[4 - POOL_ID_BYTES..].try_into().unwrap()
}
