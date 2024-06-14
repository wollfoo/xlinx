import hashlib
import base58
import bech32
import requests
import time
import json
import urllib.parse
from mnemonic import Mnemonic
from Crypto.Hash import RIPEMD

# Tải cài đặt cấu hình
def load_config():
    with open('settings.json', 'r', encoding='utf-8') as f:
        return json.load(f)

# Lưu cài đặt cấu hình cập nhật
def save_config(config):
    with open('settings.json', 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False)
    print("saved checked")

def hash160(data):
    sha = hashlib.sha256(data).digest()
    rip = RIPEMD.new(sha).digest()
    return rip

def checksum(data):
    sha256_1 = hashlib.sha256(data).digest()
    sha256_2 = hashlib.sha256(sha256_1).digest()
    return sha256_2[:4]

def encode_base58_check(data):
    return base58.b58encode(data + checksum(data))

def public_key_to_p2pkh(public_key):
    key_hash = hash160(public_key)
    return encode_base58_check(b'\x00' + key_hash).decode('utf-8')

def public_key_to_p2sh(public_key):
    key_hash = hash160(public_key)
    return encode_base58_check(b'\x05' + key_hash).decode('utf-8')

def public_key_to_bech32(public_key):
    key_hash = hash160(public_key)
    witness_version = 0
    return bech32.encode('bc', witness_version, key_hash)

# Tạo địa chỉ Bitcoin từ khóa công khai và in ra địa chỉ ví
def public_key_to_address(public_key):
    try:
        public_key_bytes = base58.b58decode(public_key)  # Giải mã từ Base58

        p2pkh_address = public_key_to_p2pkh(public_key_bytes)
        p2sh_address = public_key_to_p2sh(public_key_bytes)
        bech32_address = public_key_to_bech32(public_key_bytes)

        return p2pkh_address, p2sh_address, bech32_address
    except Exception as e:
        print(f"Lỗi khi chuyển đổi khóa công khai: {e}")
        return None, None, None

# Yêu cầu thông tin số dư cho các địa chỉ đã cho
def request_balances(stringaddress, addresses, mnemonics):
    try:
        url = f'https://blockchain.info/balance?active={stringaddress}'
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        for address, mnemonic in zip(addresses, mnemonics):
            if address in data and 'final_balance' in data[address]:
                balance = data[address]['final_balance'] / 100000000  # chuyển đổi từ satoshi sang BTC
                if balance > 0:
                    print(f'Số dư: {balance} BTC')
                    print(f'Mnemonic: {mnemonic}')
                    print(f'Địa chỉ ví: {address}')
                    with open('wallets.txt', 'a', encoding='utf-8') as file:
                        file.write(f"Mnemonic: {mnemonic}, Address: {address}, Balance: {balance} BTC\n")
            else:
                print(f"Không tìm thấy khóa 'final_balance' trong dữ liệu trả về của Blockchain.info API cho địa chỉ {address}")
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 429:
            print(f"Lỗi: Yêu cầu API không thành công với mã trạng thái 429 (quá giới hạn tốc độ). Chờ 60 giây và thử lại...")
            time.sleep(60)  # Chờ 60 giây trước khi thử lại
            request_balances(stringaddress, addresses, mnemonics)  # Thử lại với cùng chuỗi địa chỉ và mnemonics
        else:
            print(f"Lỗi HTTP: {http_err}")
    except requests.exceptions.RequestException as err:
        print(f"Lỗi yêu cầu: {err}")
    except json.JSONDecodeError:
        print(f"Lỗi: Phản hồi không phải là JSON hợp lệ cho địa chỉ {address}")
    except Exception as e:
        print(f"Lỗi: {e}. Chương trình sẽ khởi động lại sau 5 giây...")
        time.sleep(5)

# Thu thập thông tin địa chỉ và yêu cầu số dư
def get_address_info(addresses, mnemonics):
    # Chuỗi địa chỉ ví để gửi yêu cầu kiểm tra số dư
    stringaddress = urllib.parse.quote_plus('|'.join(addresses))
    # Gửi yêu cầu kiểm tra số dư
    request_balances(stringaddress, addresses, mnemonics)

def main():
    config = load_config()
    checked = config.get('checked', 0)  # Đảm bảo giá trị mặc định nếu không tồn tại
    speed = config.get("speed", 1)  # Đảm bảo giá trị mặc định nếu không tồn tại
    batch_size = config.get("batch_size", 50)  # Đảm bảo giá trị mặc định nếu không tồn tại

    while True:  # Vòng lặp vô hạn để liên tục tạo ví và kiểm tra số dư
        mnemonics = []
        addresses = []
        while checked < ((checked // batch_size) + ((checked % batch_size != 0) * 1)) * batch_size:
            mnemo = Mnemonic("czech").generate(strength=128)  # Tạo mnemonic mới với độ mạnh 128 bit
            print(f"wallet checked {checked}: {mnemo}")  # In ra thông tin của mỗi ví đã kiểm tra
            private_key = Mnemonic.to_seed(mnemo, passphrase='')  # Tạo khóa riêng tư từ mnemonic
            public_key = Mnemonic.to_hd_master_key(private_key)  # Tạo khóa công khai từ khóa riêng tư
            p2pkh_address, p2sh_address, bech32_address = public_key_to_address(public_key)  # Tạo địa chỉ ví từ khóa công khai

            # Thêm mnemonic và các địa chỉ vào danh sách nếu không bị lỗi
            if p2pkh_address and p2sh_address and bech32_address:
                mnemonics.extend([mnemo, mnemo, mnemo])
                addresses.extend([p2pkh_address, p2sh_address, bech32_address])

            checked += 1  # Tăng số lượng ví đã kiểm tra
            time.sleep(speed)  # Chờ một khoảng thời gian trước khi tạo ví tiếp theo

        # Cập nhật biến `checked` trong cấu hình và lưu lại cấu hình
        config['checked'] = checked
        save_config(config)

        checked += 1
        # Kiểm tra số dư cho các địa chỉ đã tạo
        get_address_info(addresses, mnemonics)

if __name__ == "__main__":
    main()
