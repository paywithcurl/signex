defmodule SignEx do
  require Logger
  require SignEx.Algorithm
  alias SignEx.Algorithm
  import SignEx.Helper

  @digest Algorithm.default_digest()
  @digest_str Algorithm.humanize_digest(@digest)
  @allowed_algorithms Algorithm.allowed_strings()

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
    params = %SignEx.Parameters{algorithm: algorithm_str},
    public_key) when is_binary(public_key) and algorithm_str in @allowed_algorithms
  do
    algorithm = Algorithm.new(algorithm_str)
    case Base.decode64(params.signature) do
      {:ok, signature} ->
        case fetch_keys(headers, params.headers) do
          {:ok, ordered_headers} ->
            signing_string = compose_signing_string(ordered_headers)
            :public_key.verify(signing_string, algorithm.digest, signature, decode_key(public_key))
          {:error, _reason} ->
            false
        end
      :error ->
        false
    end
  end

  def generate_digest(body) do
    Algorithm.humanize_digest(@digest) <> "=" <> Base.encode64(digest_content(body))
  end

  def digest_content(content) do
    :crypto.hash(@digest, content)
  end

  def digest_valid?(content, @digest_str <> "=" <> digest) do
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
