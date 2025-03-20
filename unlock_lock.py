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
    Redeemer,
    UTxO
)
from pycardano.hash import (
    VerificationKeyHash,
    TransactionId,
    ScriptHash,
)
import cbor2
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
    utxo: UTxO,
    amount: int,
    into: ScriptHash,
    datum: PlutusData,
    from_script: PlutusV3Script,
    redeemer: Redeemer,
    signing_key: PaymentSigningKey,
    owner: VerificationKeyHash,
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
    builder.add_script_input(
        utxo=utxo,
        script=from_script,
        redeemer=redeemer,
    )
    builder.add_input_address(input_address)
    builder.add_output(
        TransactionOutput(
            address=input_address,
            amount=utxo.output.amount.coin,
        )
    )
    builder.required_signers = [owner]
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

 
def get_utxo_from_str(paymentkey_hash: VerificationKeyHash,contract_address: Address) -> UTxO:
    # print(contract_address)
    # print(context.utxos(str(contract_address)))
    for utxo in context.utxos(str(contract_address)):
        outputdatum = cbor2.loads(utxo.output.datum.cbor)
        param = HelloWorldDatum(owner=outputdatum.value[0])
        if str(paymentkey_hash) == str(param.owner.hex()):
            # print(str(param.owner.hex()) + " - " + str(paymentkey_hash))
            return utxo
    raise Exception(f"UTxO not found for transaction {paymentkey_hash}")

@dataclass
class HelloWorldRedeemer(PlutusData):
    CONSTR_ID = 0

@dataclass
class HelloWorldDatum(PlutusData):
    CONSTR_ID = 0
    owner: bytes
 
signing_key = PaymentSigningKey.load("me.sk")
 
validator = read_validator()
 
owner = PaymentVerificationKey.from_signing_key(signing_key).hash()
 
datum = HelloWorldDatum(owner=owner.to_primitive())

redeemer = Redeemer(data=HelloWorldRedeemer())

utxo = get_utxo_from_str(owner, Address(
    payment_part = validator["script_hash"],
    network=Network.TESTNET,
))

tx_hash = lock(
    utxo=utxo,
    amount=2_000_000,
    into=validator["script_hash"],
    datum=datum,
    redeemer=redeemer,
    from_script=validator["script_bytes"],
    signing_key=signing_key,
    owner=PaymentVerificationKey.from_signing_key(signing_key).hash(),
    context=context,
)
 
print(
    f"2 tADA locked into the contract\n\tTx ID: {tx_hash}\n\tDatum: {datum.to_cbor_hex()}"
)