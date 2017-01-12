defmodule SignEx do
  import SignEx.Helper

  def sign(body, metadata, keypair) do
    metadata = Map.merge(metadata, %{"digest" => generate_digest(body)})
    parameters = SignEx.Signer.sign(metadata, keypair)
    {:ok, {metadata, parameters}}
  end

  def signature_valid?(
    headers,
    params = %SignEx.Parameters{algorithm: algorithm},
    public_key) when is_binary(public_key) and algorithm in ["rsa-sha512", "ec-sha512"] do
    case Base.decode64(params.signature) do
      {:ok, signature} ->
        case fetch_keys(headers, params.headers) do
          {:ok, ordered_headers} ->
            signing_string = compose_signing_string(ordered_headers)
            :public_key.verify(signing_string, :sha512, signature, decode_key(public_key))
          {:error, _reason} ->
            false
        end
      :error ->
        false
    end
  end

  def generate_digest(body) do
    "SHA-256=" <> Base.encode64(digest_content(body))
  end

  def digest_content(content) do
    :crypto.hash(:sha256, content)
  end

  def digest_valid?(content, "SHA-256=" <> digest) do
    case Base.decode64(digest) do
      {:ok, digest} ->
        digest == digest_content(content)
      :error ->
        false
    end
  end

  def verified?(body, metadata, params, keystore) do
    digest = metadata["digest"]
    digest && digest_valid?(body, digest) && signature_valid?(metadata, params, keystore)
  end
  # verify -> {content, signed metadata only}
  def signature_params(str) do
    SignEx.Parameters.parse(str)
  end
end
