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

## How test keys were generated

### EC

* `openssl ecparam -out ec_private_key.pem -name secp521r1 -genkey`
* `openssl ec -in ec_private_key.pem -pubout -out ec_public_key.pem`

### RSA

* `openssl genrsa -out private_key.pem 2048`
* `openssl rsa -in private_key.pem -pubout > public_key.pem`
