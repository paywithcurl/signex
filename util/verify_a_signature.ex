# quick a dirty script for verifying signature
# against a public key.

# inputs:
public_key = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEe0bCbJwcY/pp8DAb0FhdxHTjQ0iA
CpmmGiLKgDaJepnrzBkhY77s083bRpoPjSpsKlS2eRuo7sJ4oaacz+0CdA==
-----END PUBLIC KEY-----
"""
signature = "MEUCIE2a8zjhzFkHaIw4bXWAhgWhICVcJNMRlosiml7wbsNnAiEArktH\/NtvDq6H2sD65Ysjz8ha3PkanbhMBPKhJvOFZY0="
signing_string = "digest: SHA-512=6x0GhvDkdNaXtkzl+f0uxLel9GlZalu5z50PEvjM\/WxUuf0xEJd6oS3uqysvuDaICmJABjqoY7dK00BKBVTM3g=="

# decode the signature
{:ok, decoded_signature} = Base.decode64(signature)

# decode the public key
[key_entry] = :public_key.pem_decode(public_key)
decoded_key = :public_key.pem_entry_decode(key_entry)

# assume the algo digest is sha256
algo_digest = :sha256

IO.puts :public_key.verify(signing_string, algo_digest, decoded_signature, decoded_key)
