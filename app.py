from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
from secret import *
import uid_generator_pb2
import requests
from flask import Flask, jsonify
from zitado_pb2 import Users
import time
import os

app = Flask(__name__)

accounts = [
("4212660350","DEV_TEAM-V31VE1CJF-JNIYEN"),
("4212660486","DEV_TEAM-BTGGFKGTK-JNIYEN"),
("4212660568","DEV_TEAM-AQJTOCDJP-JNIYEN"),
("4212660673","DEV_TEAM-V3WCBOJ14-JNIYEN"),
("4212660773","DEV_TEAM-ALQ0CNB6P-JNIYEN"),
("4212660872","DEV_TEAM-SR862SN14-JNIYEN"),
("4212660976","DEV_TEAM-BLOJCS6P3-JNIYEN"),
]

current_account_index = 0

def get_account():
    global current_account_index
    if not accounts:
        raise Exception("No accounts available!")
    return accounts[current_account_index]

def rotate_account():
    global current_account_index
    current_account_index += 1
    if current_account_index >= len(accounts):
        current_account_index = 0
    uid, pwd = accounts[current_account_index]
    print(f"Switched to account index {current_account_index} -> UID {uid}")

def fetch_token_from_api(uid: str, password: str, timeout=8):
    url = f"https://steve-jwt-v3.vercel.app/token?uid={uid}&password={password}"
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("token")
            if token:
                print(f"Token fetched for UID {uid}")
                return token
        print(f"Token API error for UID {uid}: {resp.status_code}")
    except Exception as e:
        print(f"Error fetching token for UID {uid}: {e}")
    return None

def create_protobuf(saturn_, garena):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = saturn_
    message.garena = garena
    return message.SerializeToString()

def protobuf_to_hex(protobuf_data):
    return binascii.hexlify(protobuf_data).decode()

def encrypt_aes(hex_data, key, iv):
    key_b = key.encode()[:16]
    iv_b = iv.encode()[:16]
    cipher = AES.new(key_b, AES.MODE_CBC, iv_b)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def decode_hex(hex_string):
    byte_data = binascii.unhexlify(hex_string.replace(' ', ''))
    users = Users()
    users.ParseFromString(byte_data)
    return users

def apis_with_rotation(idd_hex: str):
    attempts = 0
    max_attempts = len(accounts)
    while attempts < max_attempts:
        uid, pwd = get_account()
        token = fetch_token_from_api(uid, pwd)
        if not token:
            rotate_account()
            attempts += 1
            continue
        headers = {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
            'Connection': 'Keep-Alive',
            'Expect': '100-continue',
            'Authorization': f'Bearer {token}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = bytes.fromhex(idd_hex)
        try:
            resp = requests.post('https://clientbp.ggblueshark.com/GetPlayerPersonalShow', headers=headers, data=data, timeout=12)
            content_lower = resp.content.lower()
            if resp.status_code == 401 or b"token is expired" in content_lower:
                rotate_account()
                attempts += 1
                continue
            return resp.content.hex()
        except Exception as e:
            print(f"Request error: {e}")
            rotate_account()
            attempts += 1
            continue
    raise Exception("All accounts failed!")

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/<uid>', methods=['GET'])
def main(uid):
    try:
        saturn_ = int(uid)
        garena = 1
        protobuf_data = create_protobuf(saturn_, garena)
        protobuf_hex = protobuf_to_hex(protobuf_data)
        encrypted_hex = encrypt_aes(protobuf_hex, key, iv)
        try:
            infoo_hex = apis_with_rotation(encrypted_hex)
        except Exception as e:
            return jsonify({"error": "AllAccountsFailed", "details": str(e)}), 500
        if not infoo_hex:
            return jsonify({"error": "empty_response"}), 400
        text_preview = bytes.fromhex(infoo_hex).decode(errors='ignore')
        try:
            users = decode_hex(infoo_hex)
        except Exception as e:
            return jsonify({"error": "DecodeError", "details": str(e), "raw_preview": text_preview[:300]}), 500
        result = {}
        if users.basicinfo:
            result['basicinfo'] = []
            for user_info in users.basicinfo:
                result['basicinfo'].append({
                    'username': user_info.username,
                    'region': user_info.region,
                    'level': user_info.level,
                    'Exp': user_info.Exp,
                    'bio': users.bioinfo[0].bio if users.bioinfo else None,
                    'banner': user_info.banner,
                    'avatar': user_info.avatar,
                    'brrankscore': user_info.brrankscore,
                    'BadgeCount': user_info.BadgeCount,
                    'likes': user_info.likes,
                    'lastlogin': user_info.lastlogin,
                    'csrankpoint': user_info.csrankpoint,
                    'csrankscore': user_info.csrankscore,
                    'brrankpoint': user_info.brrankpoint,
                    'createat': user_info.createat,
                    'OB': user_info.OB
                })
        if users.claninfo:
            result['claninfo'] = []
            for clan in users.claninfo:
                result['claninfo'].append({
                    'clanid': clan.clanid,
                    'clanname': clan.clanname,
                    'guildlevel': clan.guildlevel,
                    'livemember': clan.livemember
                })
        if users.clanadmin:
            result['clanadmin'] = []
            for admin in users.clanadmin:
                result['clanadmin'].append({
                    'idadmin': admin.idadmin,
                    'adminname': admin.adminname,
                    'level': admin.level,
                    'exp': admin.exp,
                    'brpoint': admin.brpoint,
                    'lastlogin': admin.lastlogin,
                    'cspoint': admin.cspoint
                })
        result['Owner'] = ['@steve']
        return jsonify(result)
    except ValueError:
        return jsonify({"error": "InvalidUID", "details": "UID must be an integer"}), 400
    except Exception as e:
        return jsonify({"error": "UnexpectedError", "details": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
