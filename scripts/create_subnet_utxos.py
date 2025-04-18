# scripts/create_subnet_utxos.py
"""
Script để tạo các UTXO chứa Datum khởi tạo cho Subnet trên Cardano.
(Phiên bản sửa đổi: Load skey bằng decode_hotkey_skey,
 lấy vkey trực tiếp từ skey object bằng pycardano)
"""

import logging
import os
import time
import asyncio
from typing import Union

# --- Import từ pycardano ---
from pycardano import (
    Network,
    Value,
    TransactionOutput,
    Address,
    PaymentSigningKey,      # Cần kiểu dữ liệu skey để ký
    PaymentVerificationKey, # Cần kiểu dữ liệu vkey để lấy địa chỉ
    ExtendedSigningKey,     # Sử dụng kiểu này để load ví gốc
    TransactionBuilder,
    TransactionBody,
    Transaction,
    BlockFrostChainContext,
    PlutusData,
    TransactionWitnessSet,
    VerificationKeyWitness
)

# === Import từ project Moderntensor ===
# Datum Definitions
from sdk.metagraph.metagraph_datum import (
    SubnetStaticDatum,
    SubnetDynamicDatum,
    DATUM_INT_DIVISOR
)
# Smart Contract Loading
from sdk.smartcontract.validator import (
    read_validator_dynamic_subnet,
    read_validator_static_subnet,
)
# Core Services (Chỉ dùng context)
from sdk.service.context import get_chain_context
# Key Loading
from sdk.keymanager.decryption_utils import decode_hotkey_skey
# Config (Để lấy giá trị mặc định nếu env var không set)
try:
    from sdk.config import settings as sdk_settings
except ImportError:
    sdk_settings = None
    print("Warning: Could not import sdk_settings. Using hardcoded defaults.")
# === Kết thúc Import ===


# --- Cấu hình ---
logger = logging.getLogger(__name__)

# *** Sử dụng Env Vars giống prepare_testnet_datums.py ***
hotkey_base_dir = os.getenv("HOTKEY_BASE_DIR", getattr(sdk_settings, 'HOTKEY_BASE_DIR', '.')) # Thường là '.' hoặc 'wallets'
funding_coldkey_name = os.getenv("FUNDING_COLDKEY_NAME", "kickoff")
funding_hotkey_name = os.getenv("FUNDING_HOTKEY_NAME", "hk1")
funding_password_env_var = "SUBNET1_HOTKEY_PASSWORD2"
# *** ***

# Xây dựng đường dẫn chỉ tới file khóa ký (skey)
# Đường dẫn sẽ được xây dựng bên trong decode_hotkey_skey

logger.info(f"Sử dụng base dir: {hotkey_base_dir}")
logger.info(f"Sử dụng coldkey name (thư mục ví): {funding_coldkey_name}")
logger.info(f"Sử dụng hotkey name (file skey): {funding_hotkey_name}")
# logger.info(f"Đường dẫn file khóa ký (skey) sẽ sử dụng: {payment_skey_file_path}")
logger.info(f"Biến môi trường mật khẩu: {funding_password_env_var}")

OUTPUT_ADA_LOVELACE = 2_000_000 # 2 ADA
SUBNET_NET_UID = 1

# --- Hàm helper tải khóa giống prepare_testnet_datums.py ---
def load_funding_keys(
    base_dir: str,
    coldkey_name: str,
    hotkey_name: str,
    password: str,
    network: Network
) -> tuple[ExtendedSigningKey, Address]:
    """Loads funding keys using decode_hotkey_skey and derives the address."""
    logger.info(f"🔑 Loading funding keys (Cold: '{coldkey_name}', Hot: '{hotkey_name}')...")
    try:
        payment_esk, stake_esk = decode_hotkey_skey(base_dir, coldkey_name, hotkey_name, password)
        if not payment_esk:
             raise ValueError("decode_hotkey_skey không trả về payment ExtendedSigningKey hợp lệ.")

        # Lấy verification key trực tiếp từ ESK
        payment_vkey = payment_esk.to_verification_key()

        # Lấy khóa stake nếu có
        stake_vkey = None
        if stake_esk:
            stake_vkey = stake_esk.to_verification_key()

        # Tạo địa chỉ (có thể bao gồm cả stake hash)
        funding_address = Address(payment_vkey.hash(), stake_vkey.hash() if stake_vkey else None, network=network)

        logger.info(f"✅ Funding keys loaded. Address: {funding_address}")
        # Trả về ExtendedSigningKey và Address
        return payment_esk, funding_address
    except Exception as e:
        logger.exception(f"💥 Failed to load funding keys: {e}")
        raise


# --- Khởi tạo Context và Load Ví ---
try:
    logger.info("Đang khởi tạo Chain Context...")
    context = get_chain_context()
    if hasattr(context, 'network'):
        CARDANO_NETWORK = context.network
        logger.info(f"Chain context được khởi tạo thành công cho mạng: {CARDANO_NETWORK.name}")
    else:
        CARDANO_NETWORK = Network.TESTNET
        logger.warning(f"Không tìm thấy thông tin mạng từ context, sử dụng mặc định: {CARDANO_NETWORK.name}")

    # Load mật khẩu từ biến môi trường
    password = os.getenv(funding_password_env_var, "sonlearn2003")
    if not password:
        logger.warning(f"Biến môi trường '{funding_password_env_var}' chưa được đặt.")
    else:
        logger.info(f"Đã đọc mật khẩu từ biến môi trường '{funding_password_env_var}'.")

    # Gọi hàm helper để load khóa và địa chỉ
    funding_esk, funding_address = load_funding_keys(
        base_dir=hotkey_base_dir,
        coldkey_name=funding_coldkey_name,
        hotkey_name=funding_hotkey_name,
        password=password,
        network=CARDANO_NETWORK
    )

    logger.info("Đang lấy thông tin block cuối cùng...")
    current_slot = context.last_block_slot
    logger.info(f"Current slot: {current_slot}")

except FileNotFoundError as e:
     logger.error(f"Lỗi: {e}")
     exit(1)
except ImportError as e:
     logger.error(f"Lỗi import: Không tìm thấy hàm hoặc module cần thiết. Lỗi: {e}")
     exit(1)
except Exception as e:
    logger.exception(f"Lỗi không xác định khi khởi tạo context hoặc tải/giải mã ví: {e}")
    exit(1)

# --- Tải Validator Scripts và Tạo Địa chỉ ---
# (Giữ nguyên)
try:
    logger.info("Đang đọc thông tin Plutus scripts...")
    dynamic_script_info = read_validator_dynamic_subnet()
    static_script_info = read_validator_static_subnet()

    if not dynamic_script_info or not static_script_info:
        logger.error("Không thể đọc được thông tin validator script từ file JSON.")
        exit(1)

    dynamic_script_hash = dynamic_script_info['script_hash']
    static_script_hash = static_script_info['script_hash']

    dynamic_script_address = Address(dynamic_script_hash, network=CARDANO_NETWORK)
    static_script_address = Address(static_script_hash, network=CARDANO_NETWORK)

    logger.info(f"Địa chỉ Dynamic Subnet Script (cho SubnetDynamicDatum): {dynamic_script_address}")
    logger.info(f"Địa chỉ Static Subnet Script (cho SubnetStaticDatum): {static_script_address}")
except Exception as e:
    logger.exception(f"Lỗi khi đọc script hoặc tạo địa chỉ: {e}")
    exit(1)


# --- Định nghĩa và Tạo các Đối tượng Datum ---
# (Giữ nguyên)
try:
    logger.info("Đang chuẩn bị dữ liệu Datum...")
    # Lấy verification key
    owner_vkey = funding_esk.to_verification_key()
    # Lấy hash (VerificationKeyHash object)
    owner_address_hash_obj = owner_vkey.hash()
    # Lấy payload (bytes) từ hash object
    owner_address_hash_bytes = owner_address_hash_obj.payload

    logger.info(f"Owner address hash: {owner_address_hash_bytes.hex()}") # Log giá trị hex từ bytes

    static_datum = SubnetStaticDatum(
        net_uid=SUBNET_NET_UID,
        name=f"ModernTensor Subnet {SUBNET_NET_UID} - Image Generation".encode('utf-8'),
        owner_addr_hash=owner_address_hash_bytes, # <<< Gán đúng kiểu bytes
        max_miners=1024, max_validators=128, immunity_period_slots=17280,
        creation_slot=current_slot,
        description=f"Decentralized image generation services for Subnet {SUBNET_NET_UID}".encode('utf-8'),
        version=1,
        min_stake_miner=500 * 1_000_000, min_stake_validator=2000 * 1_000_000
    )
    logger.info(f"Đã tạo SubnetStaticDatum cho net_uid={SUBNET_NET_UID}")

    dynamic_datum = SubnetDynamicDatum(
        net_uid=SUBNET_NET_UID,
        scaled_weight=int(1.0 * DATUM_INT_DIVISOR),
        scaled_performance=int(0.0 * DATUM_INT_DIVISOR),
        current_epoch=0, 
        registration_open=1,
        reg_cost=10 * 1_000_000,
        scaled_incentive_ratio=int(0.5 * DATUM_INT_DIVISOR),
        last_update_slot=current_slot, total_stake=0, validator_count=0, miner_count=0
    )
    logger.info(f"Đã tạo SubnetDynamicDatum cho net_uid={SUBNET_NET_UID}")

except Exception as e:
    logger.exception(f"Lỗi khi tạo đối tượng Datum: {e}")
    exit(1)


# --- Định nghĩa Giá trị Output ---
output_value = Value.from_primitive([OUTPUT_ADA_LOVELACE])

# --- Hàm chính thực thi việc tạo UTXO ---
async def main():
    logger.info("===== BẮT ĐẦU QUÁ TRÌNH TẠO UTXO KHỞI TẠO SUBNET (Trong 1 giao dịch) =====")
    tx_id = None # Khởi tạo tx_id

    try:
        # 1. Chuẩn bị các Transaction Outputs
        logger.info("Chuẩn bị TransactionOutput cho Static Datum...")
        static_tx_output = TransactionOutput(
            address=static_script_address,
            amount=output_value,
            datum=static_datum  # <<< Sử dụng inline datum
        )
        logger.info(f"  - Địa chỉ: {static_script_address}")
        logger.info(f"  - Giá trị: {output_value}")
        # Log datum CBOR thay vì hash
        logger.info(f"  - Inline Datum (CBOR): {static_datum.to_cbor_hex()}") 

        logger.info("Chuẩn bị TransactionOutput cho Dynamic Datum...")
        dynamic_tx_output = TransactionOutput(
            address=dynamic_script_address,
            amount=output_value,
            datum=dynamic_datum # <<< Sử dụng inline datum
        )
        logger.info(f"  - Địa chỉ: {dynamic_script_address}")
        logger.info(f"  - Giá trị: {output_value}")
        # Log datum CBOR thay vì hash
        logger.info(f"  - Inline Datum (CBOR): {dynamic_datum.to_cbor_hex()}") 

        # 2. Xây dựng giao dịch
        logger.info("Khởi tạo Transaction Builder...")
        builder = TransactionBuilder(context)

        logger.info("Thêm các outputs vào builder...")
        builder.add_output(static_tx_output)
        builder.add_output(dynamic_tx_output)

        logger.info(f"Thêm địa chỉ input: {funding_address}")
        builder.add_input_address(funding_address)

        # Add required signers (chính là hash của vkey tương ứng với skey dùng để ký)
        # Lấy hash từ verification key của funding_esk
        signer_hash = funding_esk.to_verification_key().hash()
        logger.info(f"Thêm required signer: {signer_hash.payload.hex()}")
        builder.required_signers = [signer_hash]

        logger.info("Đang xây dựng Transaction Body...")
        # Build transaction để tính toán fee
        tx_body = builder.build(change_address=funding_address)
        logger.info(f"Transaction Fee ước tính: {tx_body.fee / 1_000_000} ADA")

        # 3. Ký và gửi giao dịch
        logger.info("Đang ký giao dịch...")
        # Tạo chữ ký bằng cách ký vào hash của tx_body
        signature = funding_esk.sign(tx_body.hash())

        # Lấy verification key
        vkey = funding_esk.to_verification_key()

        # Tạo TransactionWitnessSet
        witness_set = TransactionWitnessSet(vkey_witnesses=[VerificationKeyWitness(vkey, signature)])

        # Tạo Transaction hoàn chỉnh
        transaction = Transaction(tx_body, witness_set)

        logger.info(f"Giao dịch đã được ký. Kích thước: {len(transaction.to_cbor())} bytes")

        logger.info("Đang gửi giao dịch (chứa cả 2 UTXO) lên mạng Cardano...")
        tx_id = context.submit_tx_cbor(transaction.to_cbor()) # <<< Sử dụng đúng tên phương thức
        logger.info("Gửi giao dịch thành công!")
        logger.info(f"Transaction ID: {tx_id}")

        # --- Thêm log link explorer --- 
        try:
            network_type = context.network
            if network_type == Network.MAINNET: explorer_url = "https://cexplorer.io"
            elif network_type == Network.PREPROD: explorer_url = "https://preprod.cexplorer.io" # Hoặc preview nếu dùng preview
            elif network_type == Network.PREVIEW: explorer_url = "https://preview.cexplorer.io"
            # Thêm các mạng testnet khác nếu cần
            else: explorer_url = f"[{network_type.name} Explorer]"
        except AttributeError:
            logger.warning("Không thể xác định mạng từ context để tạo link explorer.")
            explorer_url = "[Explorer URL N/A]"
        logger.info(f"Xem trên explorer: {explorer_url}/tx/{tx_id}")
        # --- Kết thúc log link explorer ---

    except Exception as e:
        logger.exception(f"Lỗi nghiêm trọng khi tạo/gửi giao dịch gộp: {e}")
        # tx_id sẽ vẫn là None nếu lỗi xảy ra trước khi gửi

    logger.info("===== KẾT THÚC QUÁ TRÌNH TẠO UTXO KHỞI TẠO SUBNET =====")
    if tx_id:
        logger.info("Giao dịch tạo cả hai UTXO khởi tạo đã được gửi thành công.")
        logger.info(f"TX ID: {tx_id}")
    else:
        logger.error("Không thể tạo và gửi giao dịch gộp. Vui lòng kiểm tra log chi tiết.")


# --- Điểm vào của script ---
if __name__ == "__main__":
    logger.info(f"Chạy script khởi tạo UTXO cho Subnet UID: {SUBNET_NET_UID}")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Quá trình bị dừng bởi người dùng (Ctrl+C).")
    except Exception as e:
        logger.exception("Lỗi không mong muốn trong quá trình chạy chính.")