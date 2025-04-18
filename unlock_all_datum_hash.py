"""
Script để unlock các UTXO từ contract sử dụng datum_hash.

Cảnh báo: Script này yêu cầu tái tạo chính xác các đối tượng Datum gốc
đã được hash, bao gồm cả các giá trị slot chính xác được sử dụng
khi tạo UTXO ban đầu. Nếu các giá trị slot không khớp, hash sẽ
không khớp và giao dịch sẽ thất bại.
"""

import logging
import os
import sys
import asyncio
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Tuple, List

# --- Import từ pycardano ---
from pycardano import (
    Network,
    Address,
    PaymentSigningKey,
    PaymentVerificationKey,
    ExtendedSigningKey,
    PlutusData,
    PlutusV3Script,
    Redeemer,
    ScriptHash,
    TransactionBuilder,
    TransactionOutput,
    UTxO,
    BlockFrostChainContext,
    TransactionId,
    VerificationKeyHash,
    Value
)

# --- Thêm đường dẫn gốc của project vào sys.path --- 
# (Giả sử script này nằm trong cùng thư mục scripts)
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
# -------------------------------------------------

# --- Import từ SDK Moderntensor (Cần thiết cho Datum và Context) ---
try:
    from sdk.metagraph.metagraph_datum import (
        SubnetStaticDatum,
        SubnetDynamicDatum,
        DATUM_INT_DIVISOR # Cần cho việc tái tạo datum động
    )
    from sdk.service.context import get_chain_context
    from sdk.keymanager.decryption_utils import decode_hotkey_skey
    from sdk.smartcontract.validator import (
        read_validator_dynamic_subnet, # Dùng để lấy hash của script dynamic
        read_validator_static_subnet,  # Dùng để lấy hash của script static
    )
    from sdk.config.settings import settings as sdk_settings
except ImportError as e:
    print(f"❌ FATAL: Import Error in unlock_all_datum_hash.py: {e}")
    print("   Ensure this script is run from the correct directory or PYTHONPATH is set.")
    sys.exit(1)

# --- Cấu hình Logging --- 
# (Bạn có thể thêm RichHandler nếu muốn)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
# ------------------------

# --- Constants & Configuration (Lấy từ create_subnet_utxos.py và điều chỉnh) ---
SUBNET_NET_UID = 1 # Phải khớp với giá trị khi tạo datum

# *** THAY ĐỔI CÁC GIÁ TRỊ SLOT NÀY CHO KHỚP VỚI LẦN CHẠY create_subnet_utxos.py ***
# !!! QUAN TRỌNG: Nếu các slot này không chính xác, hash sẽ không khớp !!!
# Bạn có thể cần lấy giá trị này từ log của lần chạy trước hoặc từ blockchain explorer.
CREATION_SLOT_USED = 89289221 # <<< THAY THẾ BẰNG SLOT THỰC TẾ KHI TẠO STATIC DATUM
LAST_UPDATE_SLOT_USED = 89289221 # <<< THAY THẾ BẰNG SLOT THỰC TẾ KHI TẠO DYNAMIC DATUM
# ---------------------------------------------------------------------------------

# Thông tin ví dùng để ký giao dịch unlock (giống funding key trong create_subnet_utxos)
hotkey_base_dir = os.getenv("HOTKEY_BASE_DIR", getattr(sdk_settings, 'HOTKEY_BASE_DIR', '.'))
funding_coldkey_name = os.getenv("FUNDING_COLDKEY_NAME", "kickoff")
funding_hotkey_name = os.getenv("FUNDING_HOTKEY_NAME", "hk1")
funding_password_env_var = "SUBNET1_HOTKEY_PASSWORD2"
funding_password = os.getenv(funding_password_env_var, "sonlearn2003") # Lấy mật khẩu

# --- Helper Functions (Load key, get network - Tương tự create_subnet_utxos) ---
def get_network() -> Network:
    network_str = (os.getenv("CARDANO_NETWORK") or getattr(sdk_settings, 'CARDANO_NETWORK', 'TESTNET')).upper()
    return Network.MAINNET if network_str == "MAINNET" else Network.TESTNET

def load_signing_keys(
    base_dir: str, coldkey_name: str, hotkey_name: str, password: str, network: Network
) -> Tuple[ExtendedSigningKey, VerificationKeyHash, Address]:
    """Loads signing keys, derives VKey hash and address."""
    logger.info(f"🔑 Loading signing keys (Cold: '{coldkey_name}', Hot: '{hotkey_name}')...")
    try:
        payment_esk, stake_esk = decode_hotkey_skey(base_dir, coldkey_name, hotkey_name, password)
        if not payment_esk: raise ValueError("Failed to decode payment key")
        payment_vk = payment_esk.to_verification_key()
        owner_vkh = payment_vk.hash() # Lấy VerificationKeyHash
        stake_vk = stake_esk.to_verification_key() if stake_esk else None
        signing_address = Address(owner_vkh, stake_vk.hash() if stake_vk else None, network=network)
        logger.info(f"✅ Signing keys loaded. Address: {signing_address}")
        return payment_esk, owner_vkh, signing_address
    except Exception as e:
        logger.exception(f"💥 Failed to load signing keys: {e}")
        raise

# --- Redeemer Definition (Giả sử dùng Redeemer đơn giản) ---
@dataclass
class SimpleRedeemer(PlutusData):
    """
    Simple Redeemer structure (CONSTR_ID = 0).
    Adjust if your validator requires a different structure.
    """
    CONSTR_ID = 0

# === Hàm Unlock Chính ===
async def unlock_datum_hash(
    utxos_to_check: list[UTxO],
    static_script: PlutusV3Script,
    dynamic_script: PlutusV3Script, # Cần cả 2 script vì chúng có thể khác nhau
    static_script_hash: ScriptHash,
    dynamic_script_hash: ScriptHash,
    expected_static_datum: SubnetStaticDatum,
    expected_dynamic_datum: SubnetDynamicDatum,
    redeemer_data: PlutusData,
    signing_key: ExtendedSigningKey,
    owner_vkh: VerificationKeyHash,
    signing_address: Address, # Địa chỉ để nhận lại tiền và trả phí
    context: BlockFrostChainContext,
) -> Optional[TransactionId]:
    """
    Attempts to unlock UTxOs that were created using datum_hash.
    Requires the exact original Datum objects to be provided.
    """
    logger.info("🔧 Starting unlock process for UTxOs with datum_hash...")
    builder = TransactionBuilder(context=context)
    unlocked_count = 0
    total_value_unlocked = Value(0)
    added_inputs = set() # <<< Set để theo dõi các input đã thêm

    # Tính hash của các datum mong đợi
    expected_static_hash = expected_static_datum.hash()
    expected_dynamic_hash = expected_dynamic_datum.hash()
    logger.info(f"  - Expected Static Datum Hash: {expected_static_hash.payload.hex()}")
    logger.info(f"  - Expected Dynamic Datum Hash: {expected_dynamic_hash.payload.hex()}")

    # Input từ ví để trả phí và collateral
    logger.info(f"  - Adding input address for fees/collateral: {signing_address}")
    builder.add_input_address(signing_address)

    # Lặp qua các UTXO tìm được
    for utxo in utxos_to_check:
        # Tạo định danh duy nhất cho UTXO
        utxo_id = (utxo.input.transaction_id, utxo.input.index)

        # Bỏ qua nếu UTXO này đã được thêm
        if utxo_id in added_inputs:
            logger.debug(f"  ⏩ Skipping already processed UTXO: {utxo.input}")
            continue

        # Chỉ xử lý UTXO có datum_hash và không có inline datum
        if utxo.output.datum is None and utxo.output.datum_hash is not None:
            logger.debug(f"  🔎 Checking UTXO {utxo.input} with datum_hash: {utxo.output.datum_hash.payload.hex()}")

            # Xác định xem hash này khớp với datum nào
            matched_datum: Optional[PlutusData] = None
            script_to_use: Optional[PlutusV3Script] = None
            is_static_match = False
            is_dynamic_match = False

            # Tính toán hash của datum tái tạo MỘT LẦN để so sánh
            try:
                reconstructed_static_hash_check = expected_static_datum.hash()
                reconstructed_dynamic_hash_check = expected_dynamic_datum.hash()
                logger.debug(f"    Reconstructed Static Hash for check: {reconstructed_static_hash_check.payload.hex()}")
                logger.debug(f"    Reconstructed Dynamic Hash for check: {reconstructed_dynamic_hash_check.payload.hex()}")
            except Exception as hash_err:
                logger.error(f"    ❌ Error hashing reconstructed datums: {hash_err}. Skipping UTXO {utxo.input}")
                continue

            if utxo.output.datum_hash == reconstructed_static_hash_check:
                matched_datum = expected_static_datum
                is_static_match = True
                logger.info(f"    ✅ Found potential match with expected Static Datum Hash for UTXO {utxo.input}")
            elif utxo.output.datum_hash == reconstructed_dynamic_hash_check:
                matched_datum = expected_dynamic_datum
                is_dynamic_match = True
                logger.info(f"    ✅ Found potential match with expected Dynamic Datum Hash for UTXO {utxo.input}")
            else:
                logger.warning(f"    ⚠️ UTXO {utxo.input} datum_hash ({utxo.output.datum_hash.payload.hex()}) does not match reconstructed static or dynamic hash. Skipping.")
                continue

            # Kiểm tra xem script nào thực sự cần dùng (dựa trên địa chỉ UTXO)
            utxo_address = utxo.output.address
            if utxo_address.payment_part == static_script_hash:
                 # Chỉ chấp nhận nếu hash khớp với static datum VÀ địa chỉ là static script
                 if not is_static_match:
                      logger.warning(f"    ⚠️ UTXO {utxo.input} is at STATIC address but hash matches DYNAMIC datum reconstruction. Inconsistent state. Skipping.")
                      continue
                 script_to_use = static_script
                 logger.debug(f"      UTXO address matches static script hash.")
            elif utxo_address.payment_part == dynamic_script_hash:
                 # Chỉ chấp nhận nếu hash khớp với dynamic datum VÀ địa chỉ là dynamic script
                 if not is_dynamic_match:
                      logger.warning(f"    ⚠️ UTXO {utxo.input} is at DYNAMIC address but hash matches STATIC datum reconstruction. Inconsistent state. Skipping.")
                      continue
                 script_to_use = dynamic_script
                 logger.debug(f"      UTXO address matches dynamic script hash.")
            else:
                 logger.error(f"      ❌ UTXO {utxo.input} address {utxo_address} does not match known script hashes! Skipping.")
                 continue # Không thể unlock nếu không biết script

            if script_to_use and matched_datum:
                logger.info(f"    ➕ Adding script input: UTXO={utxo.input}, Script={script_to_use.__class__.__name__}, Datum={matched_datum.__class__.__name__}")
                # Log CBOR của datum sẽ được sử dụng
                logger.info(f"      Using Datum CBOR: {matched_datum.to_cbor_hex()}") 
                try:
                    builder.add_script_input(
                        utxo=utxo,
                        script=script_to_use,
                        datum=matched_datum, # Cung cấp datum gốc đã tái tạo
                        redeemer=Redeemer(data=redeemer_data)
                    )
                    added_inputs.add(utxo_id) # <<< Đánh dấu UTXO đã thêm
                    unlocked_count += 1
                    total_value_unlocked += utxo.output.amount
                except Exception as add_err:
                    logger.error(f"    ❌ Error adding script input for {utxo.input}: {add_err}")
        else:
            logger.debug(f"  ⏭️ Skipping UTXO {utxo.input} (has inline datum or no datum_hash).")

    # Nếu không có UTXO nào hợp lệ được thêm vào
    if unlocked_count == 0:
        logger.warning("⚠️ No UTxOs with matching datum_hash found or added successfully. Nothing to unlock.")
        return None

    logger.info(f"✅ Added {unlocked_count} script inputs to the transaction.")
    logger.info(f"   Total value to unlock: {total_value_unlocked.coin / 1_000_000} ADA")

    # Thêm output để nhận lại tiền
    # Lưu ý: Chúng ta cần đảm bảo output này đủ lớn để hợp lệ
    # Cách đơn giản là gửi toàn bộ về địa chỉ cũ, builder sẽ tính toán change
    # builder.add_output(TransactionOutput(signing_address, total_value_unlocked)) # Có thể gây lỗi nếu total < minUTXO

    # Chỉ định người ký
    builder.required_signers = [owner_vkh]

    # Build, sign, submit
    try:
        logger.info("✍️ Building and signing the unlock transaction...")
        signed_tx = builder.build_and_sign(
            signing_keys=[signing_key],
            change_address=signing_address # Gửi tiền thừa về đây
        )
        logger.info(f"   Transaction built. Fee: {signed_tx.transaction_body.fee / 1_000_000} ADA")

        logger.info(f"📤 Submitting unlock transaction...")
        # tx_id = context.submit_tx(signed_tx.to_cbor())
        # Sử dụng asyncio.to_thread nếu submit_tx không phải async
        # Hoặc kiểm tra xem context.submit_tx có phải là async không
        if asyncio.iscoroutinefunction(context.submit_tx):
             tx_id = await context.submit_tx(signed_tx.to_cbor()) # type: ignore
        else:
             tx_id = await asyncio.to_thread(context.submit_tx, signed_tx.to_cbor()) # type: ignore

        tx_id_str = str(tx_id)
        logger.info(f"✅ Unlock transaction submitted! Tx Hash: [bold green]{tx_id_str}[/]")
        network = context.network
        scan_url = f"https://preprod.cardanoscan.io/transaction/{tx_id_str}" if network == Network.TESTNET else f"https://cardanoscan.io/transaction/{tx_id_str}"
        logger.info(f"   View on Cardanoscan ({network.name}): [link={scan_url}]{scan_url}[/link]")
        return tx_id
    except Exception as submit_err:
        logger.exception(f"💥 Error building/signing/submitting unlock transaction: {submit_err}")
        return None

# === Main Execution Block ===
async def main():
    logger.info("✨ --- Starting Datum Hash Unlock Script --- ✨")
    context: Optional[BlockFrostChainContext] = None
    signing_esk: Optional[ExtendedSigningKey] = None
    owner_vkh: Optional[VerificationKeyHash] = None
    signing_address: Optional[Address] = None
    static_script_info: Optional[dict] = None
    dynamic_script_info: Optional[dict] = None

    try:
        network = get_network()
        context = get_chain_context(method="blockfrost")
        if not context: raise RuntimeError("Failed to get Blockfrost context")
        logger.info(f"🔗 Context initialized for network: {context.network.name}")

        signing_esk, owner_vkh, signing_address = load_signing_keys(
            hotkey_base_dir, funding_coldkey_name, funding_hotkey_name, funding_password, network # type: ignore
        )

        # Load cả hai validator để lấy script và hash
        static_script_info = read_validator_static_subnet()
        dynamic_script_info = read_validator_dynamic_subnet()
        if not static_script_info or not dynamic_script_info:
            raise RuntimeError("Failed to load static or dynamic validator info.")
        
        static_script = static_script_info['script_bytes']
        static_script_hash = static_script_info['script_hash']
        dynamic_script = dynamic_script_info['script_bytes']
        dynamic_script_hash = dynamic_script_info['script_hash']

        static_contract_address = Address(static_script_hash, network=context.network)
        dynamic_contract_address = Address(dynamic_script_hash, network=context.network)
        logger.info(f"  Static Contract Address: {static_contract_address}")
        logger.info(f"  Dynamic Contract Address: {dynamic_contract_address}")

        # Tái tạo chính xác các đối tượng Datum
        logger.info("🔧 Reconstructing original Datum objects...")
        # Lấy owner_address_hash_bytes từ owner_vkh đã load
        owner_address_hash_bytes = owner_vkh.payload 

        # --- !! QUAN TRỌNG !! --- 
        # Giá trị slot phải khớp với lúc tạo UTXO gốc
        # Nếu không chắc, hãy kiểm tra log hoặc explorer
        # ---------------------------
        reconstructed_static_datum = SubnetStaticDatum(
            net_uid=SUBNET_NET_UID,
            name=f"ModernTensor Subnet {SUBNET_NET_UID} - Image Generation".encode('utf-8'), # Phải giống hệt
            owner_addr_hash=owner_address_hash_bytes,
            max_miners=1024, max_validators=128, immunity_period_slots=17280,
            creation_slot=CREATION_SLOT_USED, # <<< DÙNG SLOT ĐÃ CẤU HÌNH
            description=f"Decentralized image generation services for Subnet {SUBNET_NET_UID}".encode('utf-8'), # Phải giống hệt
            version=1,
            min_stake_miner=500 * 1_000_000, min_stake_validator=2000 * 1_000_000
        )
        logger.info(f"  Reconstructed Static Datum (creation_slot={CREATION_SLOT_USED}) - Hash: {reconstructed_static_datum.hash().payload.hex()}")

        reconstructed_dynamic_datum = SubnetDynamicDatum(
            net_uid=SUBNET_NET_UID,
            scaled_weight=int(1.0 * DATUM_INT_DIVISOR),
            scaled_performance=int(0.0 * DATUM_INT_DIVISOR),
            current_epoch=0, registration_open=True, reg_cost=10 * 1_000_000,
            scaled_incentive_ratio=int(0.5 * DATUM_INT_DIVISOR),
            last_update_slot=LAST_UPDATE_SLOT_USED, # <<< DÙNG SLOT ĐÃ CẤU HÌNH
            total_stake=0, validator_count=0, miner_count=0
        )
        logger.info(f"  Reconstructed Dynamic Datum (last_update_slot={LAST_UPDATE_SLOT_USED}) - Hash: {reconstructed_dynamic_datum.hash().payload.hex()}")

        # Lấy UTXO từ cả hai địa chỉ contract
        logger.info(f"🔍 Fetching UTxOs from Static address: {static_contract_address}...")
        static_utxos = context.utxos(str(static_contract_address))
        logger.info(f"🔍 Fetching UTxOs from Dynamic address: {dynamic_contract_address}...")
        dynamic_utxos = context.utxos(str(dynamic_contract_address))
        
        all_utxos = static_utxos + dynamic_utxos
        logger.info(f"  Found {len(static_utxos)} UTxOs at static address, {len(dynamic_utxos)} UTxOs at dynamic address. Total: {len(all_utxos)}")

        if not all_utxos:
            logger.warning("No UTxOs found at either contract address. Exiting.")
            return

        # Chuẩn bị Redeemer (Giả sử SimpleRedeemer là đủ)
        redeemer_data = SimpleRedeemer()

        # Gọi hàm unlock
        await unlock_datum_hash(
            utxos_to_check=all_utxos,
            static_script=static_script,
            dynamic_script=dynamic_script,
            static_script_hash=static_script_hash,
            dynamic_script_hash=dynamic_script_hash,
            expected_static_datum=reconstructed_static_datum,
            expected_dynamic_datum=reconstructed_dynamic_datum,
            redeemer_data=redeemer_data,
            signing_key=signing_esk,
            owner_vkh=owner_vkh,
            signing_address=signing_address,
            context=context
        )

    except Exception as e:
        logger.exception(f"💥 An error occurred in the main execution block: {e}")
        sys.exit(1)

# --- Run Main Async Function --- 
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nScript interrupted by user.")
    # except Exception as e:
    #     logger.exception(f"Failed to run main: {e}") 