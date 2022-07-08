def decrypt(enc, key=b"dc67f@#$%hlsdfg"):
    key = key.replace(b" ", b"")
    length = min([0x20, len(key)])
    key = bytes(key[i] & 0x1F for i in range(length))
    dec = b""
    return bytes(enc[i] ^ key[i % length] for i in range(len(enc))
                 if enc[i] != 0xe0)


# enc = b"Xnseeitm\x7Fi~wX"
enc = b"KEP9qau"
print(decrypt(enc))