"""
This module provides functionality for viewing UTxOs in a Cardano smart contract.
It includes functions for reading the validator script, finding specific UTxOs, and displaying their details.
"""

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
    """
    Read and parse the Plutus validator script from plutus.json file.
    
    Returns:
        dict: A dictionary containing the validator script information including:
            - type: The script type (PlutusV3)
            - script_bytes: The compiled script bytes
            - script_hash: The script hash
    """
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
    """
    Unlock a single UTxO from a smart contract by building and submitting a transaction.
    
    Args:
        utxo: UTxO to unlock from the contract
        from_script: The Plutus script to spend from
        redeemer: The redeemer data for the script
        signing_key: Key to sign the transaction
        owner: Hash of the owner's verification key
        context: Blockchain context for transaction building
        
    Returns:
        TransactionId: The hash of the submitted transaction
    """
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
 
def get_utxo_from_str(paymentkey_hash: VerificationKeyHash, contract_address: Address) -> UTxO:
    """
    Find a UTxO at the contract address that belongs to a specific payment key hash.
    
    Args:
        paymentkey_hash: Hash of the payment key to search for
        contract_address: Address of the contract to search in
        
    Returns:
        UTxO: The matching UTxO
        
    Raises:
        Exception: If no matching UTxO is found
    """
    for utxo in context.utxos(str(contract_address)):
        outputdatum = cbor2.loads(utxo.output.datum.cbor)
        param = HelloWorldDatum(owner=outputdatum.value[0])
        if str(paymentkey_hash) == str(param.owner.hex()):
            return utxo
    raise Exception(f"UTxO not found for transaction {paymentkey_hash}")
 
@dataclass
class HelloWorldDatum(PlutusData):
    """Simple datum data structure containing owner information."""
    CONSTR_ID = 0
    owner: bytes

@dataclass
class HelloWorldRedeemer(PlutusData):
    """Simple redeemer data structure for the Hello World contract."""
    CONSTR_ID = 0
 
# Initialize blockchain context
context = get_chain_context()
 
# Load signing key
signing_key = PaymentSigningKey.load("me.sk")
 
# Read validator script
validator = read_validator()
 
# Calculate payment key hash
paymentkey_hash = PaymentVerificationKey.from_signing_key(signing_key).hash()

# Get UTxO to view
utxo = get_utxo_from_str(paymentkey_hash, Address(
    payment_part = validator["script_hash"],
    network=Network.TESTNET,
))

# Display UTxO details
print(utxo)
