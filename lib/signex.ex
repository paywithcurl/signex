defmodule SignEx do
  require Logger
  require SignEx.Algorithm
  alias SignEx.Algorithm
  import SignEx.Helper

  @digest_algorithm Algorithm.default_digest()
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

  def verified?(body, metadata = %{}, params= %SignEx.Parameters{}, keystore) when
      is_binary(body) do
    with {:ok, public_key} <- fetch_key(keystore, params.key_id),
         {:ok, full_digest} <- Map.fetch(metadata, "digest")
    do
      digest_valid?(body, full_digest) && signature_valid?(metadata, params, public_key)
    else
      _ -> false
    end
  end

  def generate_digest(body, digest_algorithm \\ @digest_algorithm) do
    Algorithm.humanize_digest(digest_algorithm) <> "=" <> Base.encode64(digest_content(body, digest_algorithm))
  end

  def digest_content(content, digest_algorithm \\ @digest_algorithm) do
    :crypto.hash(digest_algorithm, content)
  end

  def digest_valid?(content, full_digest) do
    with {:ok, {digest_algorithm, digest}} <- full_digest_destruct(full_digest),
         {:ok, digest} <- Base.decode64(digest)
    do
      digest == digest_content(content, digest_algorithm)
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

  defp full_digest_destruct(full_digest) do
    with {digest_algorithm_str, digest_str} <- String.split_at(full_digest, 7),
         digest_algorithm <- normalize_digest_algorithm(digest_algorithm_str),
         true <- Algorithm.allowed_digest?(digest_algorithm)
    do
      {:ok, {String.to_atom(digest_algorithm), String.trim_leading(digest_str, "=")}}
    else
      _ ->
        {:error, :parsing_full_digest}
    end
  end

  defp normalize_digest_algorithm(digest_algorithm_str) do
    digest_algorithm_str
    |> String.replace("-", "")
    |> String.downcase()
  end

end
