defmodule SignEx do
  require SignEx.Signer
  require SignEx.Verifier
  require SignEx.Helper

  def sign(message, private_key, public_key), do: SignEx.Signer.sign(message, private_key, public_key)
  def verify(message, signature, public_key), do: SignEx.Verifier.verify(message, signature, public_key)
  def signature_params(signature), do: SignEx.Helper.signature_params(signature)

  def secure(body, metadata, keypair) do
    metadata = Map.merge(metadata, %{"digest" => SignEx.HTTP.digest_header_for(body)})
    parameters = SignEx.Signer.sign(metadata, keypair)
    {:ok, {metadata, parameters}}
  end

  def signature_valid?(headers, params = %SignEx.Parameters{}, keystore) do
    "rsa-sha256" = params.algorithm
    {:ok, signature} = Base.decode64(params.signature)

    case SignEx.Helper.fetch_keys(headers, params.headers) do
      {:ok, ordered_headers} ->
        signing_string = SignEx.HTTP.compose_signing_string(ordered_headers)

        # TODO create a behaviour module for the keystore to return public_key
        public_key = keystore
        :public_key.verify(signing_string, :sha512, signature, SignEx.Helper.decode_key(public_key))
      {:error, _reason} ->
        false
    end
  end

  def digest_valid?(message, digest) do
    SignEx.HTTP.check_digest_header(digest, message)
  end

  def verified?(body, metadata, params, keystore) do
    digest = metadata["digest"]
    digest && digest_valid?(body, digest) && signature_valid?(metadata, params, keystore)
  end
  # verify -> {content, signed metadata only}
end
