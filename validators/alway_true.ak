// use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/transaction.{OutputReference, Transaction}

pub type Datum {
  owner: VerificationKeyHash,
}

validator always_true {
  spend(_datum: Option<Datum>, _redeemer: Data, _input: OutputReference, _self: Transaction) {
    True
  }
}