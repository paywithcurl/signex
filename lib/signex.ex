defmodule SignEx do
  require Logger
  import SignEx.Helper
  
  @algorithms ["rsa-sha512", "ec-sha512"]

  def sign(_body, %{"signature" => _anything}, _keypair) do
    {:error, :already_signed}
  end
  def sign(body, metadata = %{}, keypair = %{public_key: public_key, private_key: private_key}) when
      is_binary(body) and is_binary(public_key) and is_binary(private_key) do
    metadata = Map.merge(metadata, %{"digest" => generate_digest(body)})
    parameters = SignEx.Signer.sign(metadata, keypair)
    {:ok, {metadata, parameters}}
  end


  def signature_valid?(
    headers,
    params = %SignEx.Parameters{algorithm: algorithm},
    public_key) when is_binary(public_key) and algorithm in @algorithms do
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

  def verified?(body, metadata = %{}, params= %SignEx.Parameters{}, keystore) when
      is_binary(body) do
    with {:ok, public_key} <- fetch_key(keystore, params.key_id),
         {:ok, digest} <- Map.fetch(metadata, "digest")
    do
      digest_valid?(body, digest) && signature_valid?(metadata, params, public_key)
    else
      _ -> false
    end
  end

  def signature_params(str) do
    Logger.warn("Depreciated: Use `SignEx.Parameters.parse`")

    SignEx.Parameters.parse(str)
  end

  defp fetch_key(public_key, _id) when is_binary(public_key) do
    {:ok, public_key}
  end
  defp fetch_key(keystore, id) when is_function(keystore, 1) do
    keystore.(id)
  end
end
