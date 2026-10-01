

import hashlib
print(hashlib.sha256("scanme".encode()).hexdigest())
import hmac
import time 
import base64


STORED_PASSWORD_HASH = "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
STORED_BIOMETRIC_HASH = "f4c80f6fa2f2f94bbe36a7bf5f6ade6669b87577cf4e52e0bcea0eeefd5244bb"

TOTP_SECRET = "JBSWY3DPEHK3PPXP"
TIME_STEP = 30

def verify_password():
    try:
        user_password = input("Enter your password: ")
        user_hash = hashlib.sha256(user_password.encode()).hexdigest()
        
        if hmac.compare_digest(user_hash, STORED_PASSWORD_HASH):
            print("Password verification successful.")
            return True
        
        else:
            print("Password verification failed.")
            return False
        
    except Exception as e:
        print(f"Error during password verification: {e}")
        return False
    
    
def generate_totp(secret, time_step=30, digits=6):
    key = base64.b32decode(secret, casefold=True)
    counter = int(time.time() // time_step)
    counter_bytes = counter.to_bytes(8, "big")
    
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    
    offset = hmac_hash[-1] & 0x0F
    code = (
        ((hmac_hash[offset] & 0x7F)<< 24)
        | ((hmac_hash[offset + 1] & 0xFF)<< 16)
        | ((hmac_hash[offset + 2] & 0xFF)<< 8)
        | (hmac_hash[offset + 3] & 0xFF)
    )
    
    otp = code % (10 ** digits)
    return str(otp).zfill(digits)

def verify_otp():
    try: 
        current_otp = generate_totp(TOTP_SECRET, TIME_STEP)
        print("Current TOTP:", current_otp)
        
        user_otp = input("Enter the current TOTP code: ").strip()
        
        if user_otp == current_otp: 
            print("TOTP verification successful.")
            return True
        else:
            print("TOTP verification failed. Code may be expired or incorrect.")
            return False
    except Exception as e:
        print(f"Error during TOTP verification: {e}")
        return False
        
def verify_biometric():
    try: 
        biometric_input = input("Enter your biometric key (simulated): ")
        biometric_hash = hashlib.sha256(biometric_input.encode()).hexdigest()
        
        if hmac.compare_digest(biometric_hash, STORED_BIOMETRIC_HASH):
            print("Biometric verification successful. ")
            return True
        
        else:
            print("Biometric verification failed.")
            return False
        
    except Exception as e: 
        print(f"Error during biometric verification: {e}")
        return False
        
        
def main():
    print("=== Multi-factor Authentication ===")
    
    
    if not verify_password():
        print("Access denied: Password check failed.")
        return
    
   
    if not verify_otp():
        print("Access denied: TOTP check failed.")
        return
    
    
    if not verify_biometric():
        print("Access denied: Biometric check failed.")
        return
        
    print("Access granted: All authentication factors verified successfully.")
    
if __name__ == "__main__":
    main()