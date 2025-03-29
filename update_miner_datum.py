"""
This module provides functionality for updating miner data in a Cardano smart contract.
It includes functions for reading the validator script, managing UTxOs, and updating miner information
with performance metrics and rewards.
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

# Initialize blockchain context
context = get_chain_context() 

# Load issuer's signing key and derive verification key and address
issuer_skey = PaymentSigningKey.load("me.sk")
issuer_vkey = PaymentVerificationKey.from_signing_key(issuer_skey)
issuer_address = Address(issuer_vkey.hash(), network=Network.TESTNET)

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

def unlock_lock(
    utxos: list[UTxO],
    amount: int,
    into: ScriptHash,
    datum: PlutusData,
    from_script: PlutusV3Script,
    redeemer: Redeemer,
    signing_key: PaymentSigningKey,
    owner: VerificationKeyHash,
    context: BlockFrostChainContext,
) -> TransactionId:
    """
    Unlock funds from a smart contract by building and submitting a transaction.
    This version handles multiple UTxOs but only uses the first one in the list.
    
    Args:
        utxos: List of UTxOs to spend from (only the first one is used)
        amount: Amount of lovelace to lock
        into: Script hash of the contract
        datum: Plutus datum to attach to the output
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
    contract_address = Address(
        payment_part = into,
        network=Network.TESTNET,
    )
 
    # build transaction
    builder = TransactionBuilder(context=context)
    builder.add_script_input(
        utxo=utxos[0],
        script=from_script,
        redeemer=redeemer,
    )
    builder.add_input_address(input_address)
    builder.add_output(
        TransactionOutput(
            address=input_address,
            amount=utxos[0].output.amount.coin,
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
class HelloWorldRedeemer(PlutusData):
    """Simple redeemer data structure for the Hello World contract."""
    CONSTR_ID = 0

@dataclass
class HelloWorldDatum(PlutusData):
    """Simple datum data structure containing owner information."""
    CONSTR_ID = 0
    owner: bytes

@dataclass
class MinerDatum(PlutusData):
    """
    Data structure representing a miner's information in the contract.
    
    Attributes:
        uid: Unique identifier for the miner
        stake: Amount of ADA staked by the miner
        performance: Miner's performance score
        trust_score: Trustworthiness score of the miner
        accumulated_rewards: Total rewards earned by the miner
        last_evaluated: Timestamp of last performance evaluation
        history_hash: Hash of miner's historical data
        wallet_addr_hash: Hash of miner's wallet address
        status: Current status of the miner
        block_reg_at: Block number when the miner registered
    """
    CONSTR_ID = 0
    uid: bytes              # Unique identifier of the miner
    stake: int              # Amount of ADA staked
    performance: int        # Performance score
    trust_score: int        # Trust score
    accumulated_rewards: int # Accumulated rewards
    last_evaluated: int     # Last evaluation timestamp
    history_hash: bytes     # History hash
    wallet_addr_hash: bytes # Wallet address hash
    status: bytes           # Current status
    block_reg_at: int       # Registration block number
 
# Initialize signing key and validator
signing_key = PaymentSigningKey.load("me.sk")
validator = read_validator()
 
# Calculate owner's verification key hash
owner = PaymentVerificationKey.from_signing_key(signing_key).hash()
 
# Create miner datum with sample data
datum = MinerDatum(
    uid=b"miner123",
    stake=1000000,
    performance=95,
    trust_score=80,
    accumulated_rewards=500000,
    last_evaluated=123456,
    history_hash=b"abcdef",
    wallet_addr_hash=owner.to_primitive(),
    status=b"active",
    block_reg_at=654321,
)

print("CBOR of MinerDatum:", datum.to_cbor_hex())

redeemer = Redeemer(data=HelloWorldRedeemer())

# Get all UTxOs from the contract address
contract_address = Address(
    payment_part=validator["script_hash"],
    network=Network.TESTNET,
)
utxos = context.utxos(str(contract_address))  # Get all UTxOs

# Execute the unlock transaction
tx_hash = unlock_lock(
    utxos=utxos,
    amount=4_000_000,
    into=validator["script_hash"],
    datum=datum,
    redeemer=redeemer,
    from_script=validator["script_bytes"],
    signing_key=signing_key,
    owner=PaymentVerificationKey.from_signing_key(signing_key).hash(),
    context=context,
)
 
print(
    f"4 tADA locked into the contract\n\tTx ID: {tx_hash}\n\tDatum: {datum.to_cbor_hex()}"
)