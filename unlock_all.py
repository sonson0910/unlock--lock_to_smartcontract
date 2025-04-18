"""
This module provides functionality for unlocking all UTxOs from the dynamic_datum Cardano smart contract
in a single transaction. It includes functions for reading the validator script and building
transactions to unlock multiple UTxOs at once, ensuring the required datum is included.
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
    Assumes the first validator in the file is the one to use.
    
    Returns:
        dict: A dictionary containing the validator script information including:
            - type: The script type (PlutusV3)
            - script_bytes: The compiled script bytes
            - script_hash: The script hash
    """
    with open("plutus.json", "r") as f:
        validator = json.load(f)
    # Ensure we are using the correct validator based on the updated plutus.json
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
    # Redeemer might need to be updated based on the actual validator logic
    redeemer_data: PlutusData, 
    signing_key: PaymentSigningKey,
    owner: VerificationKeyHash,
    context: BlockFrostChainContext,
) -> TransactionId:
    """
    Unlock multiple UTxOs from a smart contract in a single transaction.
    Includes the necessary datum for each script input.
    
    Args:
        utxos: List of UTxOs to unlock from the contract.
        from_script: The Plutus script to spend from.
        redeemer_data: The PlutusData object for the redeemer.
        signing_key: Key to sign the transaction.
        owner: Hash of the owner's verification key (required signer).
        context: Blockchain context for transaction building.
        
    Returns:
        TransactionId: The hash of the submitted transaction.
    """
    # Read sender's address (to receive ADA after unlocking)
    with open("me.addr", "r") as f:
        input_address = Address.from_primitive(f.read())

    # Initialize TransactionBuilder
    builder = TransactionBuilder(context=context)

    # Add all UTxOs from the contract to the transaction
    total_amount = 0  # Total amount of ADA from all UTxOs
    for utxo in utxos:
        # Ensure datum exists for the UTxO
        if utxo.output.datum is None:
             print(f"Warning: UTxO {utxo.input.transaction_id}#{utxo.input.index} has no datum, skipping.")
             continue

        # Create a Redeemer for each input. Adjust if validator needs different redeemers.
        redeemer = Redeemer(data=redeemer_data) 

        builder.add_script_input(
            utxo=utxo,
            script=from_script,
            datum=utxo.output.datum,  # Provide the original datum
            redeemer=redeemer,
        )
        # print(f"Adding UTXO: {utxo.input.transaction_id}#{utxo.input.index} with datum {utxo.output.datum}")
        total_amount += utxo.output.amount.coin  # Accumulate ADA from each UTxO

    # Check if any UTxOs were actually added
    if total_amount == 0:
        raise ValueError("No valid UTxOs with datum found to unlock.")

    # Add input address (required for fees and collateral)
    # Ensure this address has sufficient funds for collateral
    builder.add_input_address(input_address)

    # Create output with total amount of ADA from all unlocked UTxOs
    builder.add_output(
        TransactionOutput(
            address=input_address,
            amount=total_amount,
        )
    )

    # Specify required signing keys
    builder.required_signers = [owner]

    # Build and sign the transaction
    # Collateral is automatically handled by builder if input_address has UTxOs
    signed_tx = builder.build_and_sign(
        signing_keys=[signing_key],
        change_address=input_address,  # Any change will be sent back to input_address
    )

    # Submit transaction
    return context.submit_tx(signed_tx)

@dataclass
class DynamicDatum(PlutusData):
    """Datum structure matching the dynamic_datum/Datum definition."""
    CONSTR_ID = 0
    subnet_id: bytes

@dataclass
class SimpleRedeemer(PlutusData):
    """
    Simple Redeemer structure (CONSTR_ID = 0).
    Adjust if your validator requires a different structure.
    """
    CONSTR_ID = 0

# --- Main Script Execution ---

# Initialize context
context = get_chain_context()

# Load signing key
signing_key = PaymentSigningKey.load("me.sk")

# Derive owner verification key hash
owner_vkh = PaymentVerificationKey.from_signing_key(signing_key).hash()

# Read validator
validator = read_validator()

# Get all UTxOs from the contract address
contract_address = Address(
    payment_part=validator["script_hash"],
    network=Network.TESTNET,
)
utxos = context.utxos(str(contract_address))  # Get all UTxOs

# Check if there are any UTxOs
if not utxos:
    raise Exception(f"No UTxOs found at the contract address: {contract_address}")

print(f"Found {len(utxos)} UTxOs at the contract address.")

# Create the redeemer data (adjust SimpleRedeemer if needed)
redeemer_data = SimpleRedeemer()

# Execute transaction to unlock all UTxOs
try:
    tx_hash = unlock(
        utxos=utxos,  # Pass list of all UTxOs
        from_script=validator["script_bytes"],
        redeemer_data=redeemer_data, # Pass the PlutusData object
        signing_key=signing_key,
        owner=owner_vkh,
        context=context,
    )

    # Print results
    print(
        f"All valid UTxOs unlocked from the contract\n"
        f"\tTx ID: {tx_hash}\n"
        f"\tRedeemer Used: {redeemer_data.to_cbor_hex()}"
    )
except Exception as e:
    print(f"Error during transaction submission: {e}")
    # Potentially print more details or re-raise depending on desired error handling