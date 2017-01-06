# signex
Secure messages through digests and signing.

SignEx can work with any message which has:
- content that can be represented as a binary, such as an HTML body.
- metadata that can be represented as a map, such as HTML headers.

Signing a message consists of two steps

- Generating a digest of the content
- Signing the message metadata which includes the content digest.


## Usage

### Signing generic messages

```elixir
content = "My exiting message!!!"
metadata = %{"my-key" => "my-value"}
{:ok, {metadata_with_digest, signature}} = SignEx.sign(content, metadata, keypair)
true = SignEx.verified?(content, metadata_with_digest, signature, keypair.public_key)
```

## SignEx.HTTP

For securing HTTP requests.

```elixir
{:ok, digest_header} = SignEx.generate_digest(body)
headers = headers ++ [{"digest", digest_header}]

{:ok, signature_header} = SignEx.HTTP.signature_header_for(headers, keypair)
headers = headers ++ [{"signature", signature_header}]
```

Would be nice to have a different word for the combination of actions other than sign.
e.g. lock, fossilise!, bond(glue), hallmark, stamp, seal

TODO: handle path psudo header
TODO: Keystore lookup

I think that the header keys should be downcased.
Makes is explicit and HTTP/2 specifies downcased headers.
plug also downcases them

## Notes
- Adding extra headers does not count as tamering with the message
- Could make the validate step delete all unverified headers

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
