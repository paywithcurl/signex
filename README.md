# signex
Sign messages with private key

## Usage

### To sign

```elixir
private_key = # read private key
public_key = # read public key
{:ok, signature, signed_message} = SignEx.sign("my message", private_key, public_key)
```

### To verify

```elixir
public_key = # read public key
case SignEx.verify("my message", signature, public_key) do
    :ok -> # success
    {:error, reason} -> # failure
end
```

## SignEx.HTTP

For securing HTTP requests.

Signing a request consists of two steps

- Generating a digest of the body content
- Signing the request headers.


```elixir
{:ok, digest_header} = SignEx.HTTP.digest_header_for(body)
headers = headers ++ [{"digest", digest_header}]

{:ok, signature_header} = SignEx.HTTP.signature_header_for(headers, keypair)
headers = headers ++ [{"signature", signature_header}]
```

As long as the digest headers is one of the signed headers then the whole request is secured.
SignEx will have to make assumptions about the request format OR have adapters for plug/httpoison etc if we are to have a single call that does all the locking a request.
Would be nice to have a different word for the combination of actions other than sign.
e.g. lock, fossilise!, bond(glue), hallmark, stamp, seal

```elixir
{:ok, request} = SignEx.HTTP.seal(request, keypair, headers: [:path, :date])
```

On server

This is example code that would make no assumptions about the format of the request,
hence leaving signex as agnostic as possible
```elixir
signature = Plug.Conn.get_req_header(conn, "signature")
{:ok, signature} = SignEx.HTTP.parse_signature(signature)
{:ok, public_key} = lookup_public_key(signature.key_id)
headers = conn.req_headers
signed_headers = SignEx.HTTP.fetch_signed_headers(headers, signature.headers)
SignEx.HTTP.verify_signed_headers(signed_headers, public_key)

digest_header = Plug.Conn.get_req_header(conn, "digest")
SignEx.HTTP.check_digest_header(digest_header, conn.body)
```

Because of the complexity in the above I thing it would be best if SignEx was packaged with plugs. `SignEx.Plug.Digest`, `SignEx.Plug.Signature`

I think that the header keys should be downcased.
Makes is explicit and HTTP/2 specifies downcased headers.
plug also downcases them

## How test keys were generated

### EC

* `openssl ecparam -out ec_private_key.pem -name secp521r1 -genkey`
* `openssl ec -in ec_private_key.pem -pubout -out ec_public_key.pem`

### RSA

* `openssl genrsa -out private_key.pem 2048`
* `openssl rsa -in private_key.pem -pubout > public_key.pem`

### Notes

- Hashes and Digests refer to the same process.
  A hash function produces a digest. hash function == digest algorithm
