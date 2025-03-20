from dataclasses import dataclass
from pycardano import (
    Address,
    BlockFrostChainContext,
    Network,
    PaymentSigningKey,
    PaymentVerificationKey,
    PlutusData,
    PlutusV3Script,
    Redeemer,
    ScriptHash,
    TransactionBuilder,
    TransactionOutput,
    UTxO,
)
from pycardano.hash import (
    VerificationKeyHash,
    TransactionId,
    ScriptHash,
)
from context import get_chain_context
import cbor2
import json
import os
import sys
 
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
 
def unlock(
    utxo: UTxO,
    from_script: PlutusV3Script,
    redeemer: Redeemer,
    signing_key: PaymentSigningKey,
    owner: VerificationKeyHash,
    context: BlockFrostChainContext,
) -> TransactionId:
    # read addresses
    with open("me.addr", "r") as f:
        input_address = Address.from_primitive(f.read())
 
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

context = get_chain_context()
 
signing_key = PaymentSigningKey.load("me.sk")
 
validator = read_validator()
 
paymentkey_hash = PaymentVerificationKey.from_signing_key(signing_key).hash()

# get utxo to spend
utxo = get_utxo_from_str(paymentkey_hash, Address(
    payment_part = validator["script_hash"],
    network=Network.TESTNET,
))
 
# build redeemer
redeemer = Redeemer(data=HelloWorldRedeemer())
 
# execute transaction
tx_hash = unlock(
    utxo=utxo,
    from_script=validator["script_bytes"],
    redeemer=redeemer,
    signing_key=signing_key,
    owner=PaymentVerificationKey.from_signing_key(signing_key).hash(),
    context=context,
)
 
print(
    f"2 tADA unlocked from the contract\n\tTx ID: {tx_hash}\n\tRedeemer: {redeemer.to_cbor_hex()}"
)