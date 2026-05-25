import socket
import binascii

host = '13.56.189.91'
port = 1337

# النص المشفر الأصلي
full_ct_hex = "89ea68027128bb18b32e24f9b702f401e9b98c5592b35c2136e377890a0ae6e5fce5d61974324e8efc8086e2a23179be8fdca60c0d9f6933d127622e811faced"

def is_padding_ok(payload_hex):
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            # قراءة كل الهري اللي السيرفر بيبعته في الأول لحد ما يطلب الـ ciphertext
            data = ""
            while "Enter a hex-encoded ciphertext" not in data:
                chunk = s.recv(1024).decode()
                if not chunk: break
                data += chunk
            
            # إرسال المحاولة
            s.sendall(payload_hex.encode() + b'\n')
            
            # قراءة الرد
            res = s.recv(1024).decode()
            
            # لو الرد مكنش فيه كلمة FAIL، يبقى البادينج سليم!
            if "FAIL" not in res and len(res) > 0:
                return True
            return False
    except:
        return False

def recover():
    ct = bytes.fromhex(full_ct_hex)
    iv = ct[:16]
    blocks = [ct[i:i+16] for i in range(16, len(ct), 16)]
    
    full_decrypted = ""
    prev_block = iv
    
    for b_idx, block in enumerate(blocks):
        print(f"\n--- Decrypting Block {b_idx + 1} ---")
        intermediate = bytearray(16)
        decrypted = bytearray(16)
        
        for i in range(1, 17):
            idx = 16 - i
            found = False
            # تجربة القيم من 0 لـ 255
            for b in range(256):
                test_prev = bytearray(prev_block)
                for j in range(idx + 1, 16):
                    test_prev[j] = intermediate[j] ^ i
                
                test_prev[idx] = b ^ i
                payload = test_prev.hex() + block.hex()
                
                if is_padding_ok(payload):
                    # Double check
                    if i < 16:
                        test_prev[idx-1] ^= 1
                        if not is_padding_ok(test_prev.hex() + block.hex()):
                            continue
                    
                    intermediate[idx] = b
                    decrypted[idx] = b ^ prev_block[idx]
                    print(f"[+] Byte {i} found: {repr(chr(decrypted[idx]))}")
                    found = True
                    break
            if not found:
                print(f"[-] Failed at byte {i}")
                return
        
        full_decrypted += "".join(chr(x) for x in decrypted if 32 <= x <= 126)
        prev_block = block
        print(f"Current Flag: {full_decrypted}")

recover()