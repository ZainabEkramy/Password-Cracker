import socket
import binascii

# الإعدادات
host = '13.56.189.91'
port = 1337

def check_padding(payload_hex):
    try:
        # بنفتح اتصال جديد لكل فحص (أو ممكن نعدله ليبقى مفتوحاً)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            # قراءة الترحيب
            s.recv(1024) 
            # إرسال البايتات المحقونة
            s.sendall(payload_hex.encode() + b'\n')
            # قراءة الرد
            response = s.recv(1024).lower()
            # بنعرف الرد صح لو مفيش كلمة error أو لو فيه كلمة correct/ok
            if b"correct" in response or b"ok" in response:
                return True
            return False
    except:
        return False

# النص المشفر المعطى
ct_hex = "89ea68027128bb18b32e24f9b702f401e9b98c5592b35c2136e377890a0ae6e5fce5d61974324e8efc8086e2a23179be8fdca60c0d9f6933d127622e811faced"
ciphertext = bytes.fromhex(ct_hex)

# تقسيم البلوكات (16 بايت لكل بلوك)
block_size = 16
iv = ciphertext[:block_size]
blocks = [ciphertext[i:i+block_size] for i in range(block_size, len(ciphertext), block_size)]

def recover_block(prev_block, current_block):
    decrypted_block = bytearray(block_size)
    intermediate_block = bytearray(block_size)
    
    # الهجوم بيبدأ من اليمين للشمال (من بايت 15 لحد 0)
    for i in range(1, block_size + 1):
        found = False
        for b in range(256):
            test_prev = bytearray(prev_block)
            
            # تجهيز البادينج للبايتات اللي عرفناها قبل كدة
            for j in range(1, i):
                test_prev[block_size - j] = intermediate_block[block_size - j] ^ i
            
            # تجربة القيمة الحالية
            test_prev[block_size - i] = b ^ i
            
            payload = test_prev.hex() + current_block.hex()
            
            if check_padding(payload):
                intermediate_block[block_size - i] = b
                decrypted_block[block_size - i] = b ^ prev_block[block_size - i]
                print(f"[+] Found byte {i}: {chr(decrypted_block[block_size - i]) if 32 <= decrypted_block[block_size - i] <= 126 else '?'}")
                found = True
                break
        if not found:
            print(f"[!] Failed to find byte {i}")
    return decrypted_block

print("Starting Padding Oracle Attack... This will take a few minutes.")
full_flag = ""
prev = iv
for idx, block in enumerate(blocks):
    print(f"--- Recovering Block {idx+1} ---")
    decoded = recover_block(prev, block)
    full_flag += decoded.decode(errors='ignore')
    prev = block
    print(f"Current string: {full_flag}")

print(f"\n[FINAL FLAG]: {full_flag}")