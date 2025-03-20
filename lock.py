from dataclasses import dataclass
from pycardano import (
    Address,
    BlockFrostChainContext,
    Network,
    PaymentSigningKey,
    PaymentVerificationKey,
    PlutusData,
    PlutusV3Script,
    ScriptHash,
    TransactionBuilder,
    TransactionOutput,
)
from pycardano.hash import (
    VerificationKeyHash,
    TransactionId,
    ScriptHash,
)
import json
import os

from context import get_chain_context

context = get_chain_context() 

issuer_skey = PaymentSigningKey.load("me.sk")
issuer_vkey = PaymentVerificationKey.from_signing_key(issuer_skey)
issuer_address = Address(issuer_vkey.hash(), network=Network.TESTNET)

def read_validator() -> dict:
    with open("plutus.json", "r") as f:
        validator = json.load(f)
    script_bytes = PlutusV3Script(
        bytes.fromhex(validator["validators"][0]["compiledCode"])
    )
    script_hash = ScriptHash(bytes.fromhex(validator["validators"][0]["hash"]))
    return {
        "type": "PlutusV3",
        "script_bytes": script_bytes,
        "script_hash": script_hash,
    }

def lock(
    amount: int,
    into: ScriptHash,
    datum: PlutusData,
    signing_key: PaymentSigningKey,
    context: BlockFrostChainContext,
) -> TransactionId:
    # read addresses
    with open("me.addr", "r") as f:
        input_address = Address.from_primitive(f.read())
    contract_address = Address(
        payment_part = into,
        network=Network.TESTNET,
    )
 
    # build transaction
    builder = TransactionBuilder(context=context)
    builder.add_input_address(input_address)
    builder.add_output(
        TransactionOutput(
            address=contract_address,
            amount=amount,
            datum=datum,
        )
    )
    signed_tx = builder.build_and_sign(
        signing_keys=[signing_key],
        change_address=input_address,
    )
 
    # submit transaction
    return context.submit_tx(signed_tx)

@dataclass
class HelloWorldDatum(PlutusData):
    CONSTR_ID = 0
    owner: bytes
 
signing_key = PaymentSigningKey.load("me.sk")
 
validator = read_validator()
 
owner = PaymentVerificationKey.from_signing_key(signing_key).hash()
 
datum = HelloWorldDatum(owner=owner.to_primitive())

tx_hash = lock(
    amount=2_000_000,
    into=validator["script_hash"],
    datum=datum,
    signing_key=signing_key,
    context=context,
)
 
print(
    f"2 tADA locked into the contract\n\tTx ID: {tx_hash}\n\tDatum: {datum.to_cbor_hex()}"
)