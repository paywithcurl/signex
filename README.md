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

would be nice to have a different word for combination.
e.g. lock, fossilise!, bond(glue), hallmark, stamp, seal

```elixir
HTTP.sign(headers, key, headers: [:path, :date])
HTTP.sign(%{headers: headers}, key)
```

on server
```elixir
{:ok, _} = SignEx.HTTP.key_id()
{:ok, _} = SignEx.HTTP.check_plug(conn, public_key)

# OR

seal = HTTP.seal_from_plug()
headers = HTTP.headers ++ request-target

```
might want to call these modules SignEx.Plug.*

I think that the header keys should be downcased.
Makes is explicit and HTTP/2 specifies downcased headers.

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
