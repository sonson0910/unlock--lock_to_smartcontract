"""
This module provides functionality for unlocking all UTxOs from a Cardano smart contract in a single transaction.
It includes functions for reading the validator script and building transactions to unlock multiple UTxOs at once.
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
    utxos: list[UTxO],
    from_script: PlutusV3Script,
    redeemer: Redeemer,
    signing_key: PaymentSigningKey,
    owner: VerificationKeyHash,
    context: BlockFrostChainContext,
) -> TransactionId:
    """
    Unlock multiple UTxOs from a smart contract in a single transaction.
    
    Args:
        utxos: List of UTxOs to unlock from the contract
        from_script: The Plutus script to spend from
        redeemer: The redeemer data for the script
        signing_key: Key to sign the transaction
        owner: Hash of the owner's verification key
        context: Blockchain context for transaction building
        
    Returns:
        TransactionId: The hash of the submitted transaction
    """
    # Read sender's address (to receive ADA after unlocking)
    with open("me.addr", "r") as f:
        input_address = Address.from_primitive(f.read())

    # Initialize TransactionBuilder
    builder = TransactionBuilder(context=context)

    # Add all UTxOs from the contract to the transaction
    total_amount = 0  # Total amount of ADA from all UTxOs
    for utxo in utxos:
        redeemer = Redeemer(data=HelloWorldRedeemer())

        builder.add_script_input(
            utxo=utxo,
            script=from_script,
            redeemer=redeemer,
        )
        print(redeemer)
        total_amount += utxo.output.amount.coin  # Accumulate ADA from each UTxO

    # Add input address (if additional UTxOs from your wallet are needed for fees)
    builder.add_input_address(input_address)

    # Create output with total amount of ADA from all UTxOs
    builder.add_output(
        TransactionOutput(
            address=input_address,
            amount=total_amount,
        )
    )

    # Specify required signing keys
    builder.required_signers = [owner]

    # Build and sign the transaction
    signed_tx = builder.build_and_sign(
        signing_keys=[signing_key],
        change_address=input_address,  # Any change will be sent back to input_address
    )

    # Submit transaction
    return context.submit_tx(signed_tx)

@dataclass
class HelloWorldRedeemer(PlutusData):
    """Simple redeemer data structure for the Hello World contract."""
    CONSTR_ID = 0

# Initialize context
context = get_chain_context()

# Load signing key
signing_key = PaymentSigningKey.load("me.sk")

# Read validator
validator = read_validator()

# Calculate payment key hash
paymentkey_hash = PaymentVerificationKey.from_signing_key(signing_key).hash()

# Get all UTxOs from the contract address
contract_address = Address(
    payment_part=validator["script_hash"],
    network=Network.TESTNET,
)
utxos = context.utxos(str(contract_address))  # Get all UTxOs

# Check if there are any UTxOs
if not utxos:
    raise Exception("No UTxOs found at the contract address")

# Create redeemer
redeemer = Redeemer(data=HelloWorldRedeemer())

# Execute transaction to unlock all UTxOs
tx_hash = unlock(
    utxos=utxos,  # Pass list of all UTxOs
    from_script=validator["script_bytes"],
    redeemer=redeemer,
    signing_key=signing_key,
    owner=PaymentVerificationKey.from_signing_key(signing_key).hash(),
    context=context,
)

# Print results
print(
    f"All UTxOs unlocked from the contract\n\tTx ID: {tx_hash}\n\tRedeemer: {redeemer.to_cbor_hex()}"
)