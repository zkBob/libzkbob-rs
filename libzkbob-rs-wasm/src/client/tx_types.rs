use crate::{Fr, IDepositData, IDepositPermittableData, ITransferData, IWithdrawData };
use libzkbob_rs::client::{TokenAmount, TxOutput, TxType as NativeTxType, ExtraItem, TxOperator};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[allow(clippy::manual_non_exhaustive)]
#[wasm_bindgen]
pub enum TxType {
    Transfer = "transfer",
    Deposit = "deposit",
    DepositPermittable = "deposit_permittable",
    Withdraw = "withdraw",
}

pub trait JsTxType {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue>;
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct TxExtraData {
    leaf_index: u8,
    pad_length: u16,
    need_encrypt: bool,
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct TxBaseFields {
    #[serde(with = "serde_bytes")]
    proxy: Vec<u8>,
    #[serde(with = "serde_bytes")]
    prover: Vec<u8>,
    proxy_fee: TokenAmount<Fr>,
    prover_fee: TokenAmount<Fr>,
    data: Vec<TxExtraData>,
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct DepositData {
    #[serde(flatten)]
    base_fields: TxBaseFields,
    amount: TokenAmount<Fr>,
}

impl JsTxType for IDepositData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let DepositData {
            base_fields,
            amount,
        } = serde_wasm_bindgen::from_value(self.into())?;

        let operator = TxOperator {
            proxy_address: base_fields.proxy,
            prover_address: base_fields.prover,
            proxy_fee: base_fields.proxy_fee,
            prover_fee: base_fields.prover_fee,
        };

        let extra = base_fields.data
            .into_iter()
            .map(|item| ExtraItem {
                leaf_index: item.leaf_index,
                pad_length: item.pad_length,
                need_encrypt: item.need_encrypt,
                data: item.data,
            })
            .collect::<Vec<_>>();

        Ok(NativeTxType::Deposit(
            operator,
            extra,
            amount,
        ))
    }
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct DepositPermittableData {
    #[serde(flatten)]
    base_fields: TxBaseFields,
    amount: TokenAmount<Fr>,
    deadline: String,
    #[serde(with = "serde_bytes")]
    holder: Vec<u8>,
}

impl JsTxType for IDepositPermittableData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let DepositPermittableData {
            base_fields,
            amount,
            deadline,
            holder,
        } = serde_wasm_bindgen::from_value(self.into())?;

        let operator = TxOperator {
            proxy_address: base_fields.proxy,
            prover_address: base_fields.prover,
            proxy_fee: base_fields.proxy_fee,
            prover_fee: base_fields.prover_fee,
        };

        let extra = base_fields.data
            .into_iter()
            .map(|item| ExtraItem {
                leaf_index: item.leaf_index,
                pad_length: item.pad_length,
                need_encrypt: item.need_encrypt,
                data: item.data,
            })
            .collect::<Vec<_>>();

        Ok(NativeTxType::DepositPermittable(
            operator,
            extra,
            amount,
            deadline.parse::<u64>().unwrap_or(0),
            holder
        ))
    }
}

#[derive(Deserialize)]
pub struct Output {
    to: String,
    amount: TokenAmount<Fr>,
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct TransferData {
    #[serde(flatten)]
    base_fields: TxBaseFields,
    outputs: Vec<Output>,
}

impl JsTxType for ITransferData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let TransferData {
            base_fields,
            outputs,
        } = serde_wasm_bindgen::from_value(self.into())?;

        let outputs = outputs
            .into_iter()
            .map(|out| TxOutput {
                to: out.to,
                amount: out.amount,
            })
            .collect::<Vec<_>>();
        
        let operator = TxOperator {
            proxy_address: base_fields.proxy,
            prover_address: base_fields.prover,
            proxy_fee: base_fields.proxy_fee,
            prover_fee: base_fields.prover_fee,
        };

        let extra = base_fields.data
            .into_iter()
            .map(|item| ExtraItem {
                leaf_index: item.leaf_index,
                pad_length: item.pad_length,
                need_encrypt: item.need_encrypt,
                data: item.data,
            })
            .collect::<Vec<_>>();

        Ok(NativeTxType::Transfer(
            operator,
            extra,
            outputs,
        ))
    }
}

#[wasm_bindgen]
#[derive(Deserialize)]
pub struct WithdrawData {
    #[serde(flatten)]
    base_fields: TxBaseFields,
    amount: TokenAmount<Fr>,
    #[serde(with = "serde_bytes")]
    to: Vec<u8>,
    native_amount: TokenAmount<Fr>,
    energy_amount: TokenAmount<Fr>,
}

impl JsTxType for IWithdrawData {
    fn to_native(&self) -> Result<NativeTxType<Fr>, JsValue> {
        let WithdrawData {
            base_fields,
            amount,
            to,
            native_amount,
            energy_amount,
        } = serde_wasm_bindgen::from_value(self.into())?;

        let operator = TxOperator {
            proxy_address: base_fields.proxy,
            prover_address: base_fields.prover,
            proxy_fee: base_fields.proxy_fee,
            prover_fee: base_fields.prover_fee,
        };

        let extra = base_fields.data
            .into_iter()
            .map(|item| ExtraItem {
                leaf_index: item.leaf_index,
                pad_length: item.pad_length,
                need_encrypt: item.need_encrypt,
                data: item.data,
            })
            .collect::<Vec<_>>();

        Ok(NativeTxType::Withdraw(
            operator,
            extra,
            amount,
            to,
            native_amount,
            energy_amount,
        ))
    }
}
