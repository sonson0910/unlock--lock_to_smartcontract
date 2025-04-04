"""
This module provides functionality for selecting and deriving wallet keys from mnemonic phrases.
It includes functions for creating both base addresses (with stake key) and enterprise addresses
(without stake key) on the Cardano testnet.
"""

import click
from pycardano import (
    Network,
    Address,
    HDWallet,
    PaymentVerificationKey,
    ExtendedSigningKey,
)


# Mnemonic phrases for different wallets
YOUR_MNEMONIC_WORDS = "wisdom sign tilt carbon cruel essence more sphere polar raw spread impulse helmet balance labor smoke chimney physical lizard trend proof age cruise trim"

OTHER_MNEMONIC_WORDS = "stay cricket black middle hunt install rival camp remind resist visual angle electric bid quiz brand day target quantum loyal ski dune hand puzzle"

def select_wallet_from_nmemonic():
    """
    Derive a base address wallet (with stake key) from the primary mnemonic phrase.
    
    Returns:
        tuple: A tuple containing:
            - spend_vk: The payment verification key
            - spend_sk: The payment signing key
            - address: The derived base address (with stake key)
    """
    hdwallet = HDWallet.from_mnemonic(YOUR_MNEMONIC_WORDS)

    # Derive payment key
    hdwallet_spend = hdwallet.derive_from_path("m/1852'/1815'/0'/0/0")
    spend_sk = ExtendedSigningKey.from_hdwallet(hdwallet_spend)
    spend_public_key = hdwallet_spend.public_key
    spend_vk = PaymentVerificationKey.from_primitive(spend_public_key)

    # Derive stake key
    hdwallet_stake = hdwallet.derive_from_path("m/1852'/1815'/0'/2/0")
    stake_public_key = hdwallet_stake.public_key
    stake_vk = PaymentVerificationKey.from_primitive(stake_public_key)

    # Create base address with both payment and stake keys
    address = Address(spend_vk.hash(), stake_vk.hash(), network=Network.TESTNET)
    return spend_vk, spend_sk, address

def select_signing_key_other():
    """
    Derive an enterprise address wallet (without stake key) from the secondary mnemonic phrase.
    
    Returns:
        tuple: A tuple containing:
            - spend_vk: The payment verification key
            - spend_sk: The payment signing key
            - address: The derived enterprise address (without stake key)
    """
    # Derive payment key
    hdwallet = HDWallet.from_mnemonic(OTHER_MNEMONIC_WORDS)
    hdwallet_spend = hdwallet.derive_from_path("m/1852'/1815'/0'/4/0")
    spend_sk = ExtendedSigningKey.from_hdwallet(hdwallet_spend)
    spend_public_key = hdwallet_spend.public_key
    spend_vk = PaymentVerificationKey.from_primitive(spend_public_key)
    
    # Create enterprise address with only payment key
    address = Address(spend_vk.hash(), network=Network.TESTNET)
    return spend_vk, spend_sk, address
