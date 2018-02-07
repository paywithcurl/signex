defmodule SignEx.Helper do

  def compose_signing_string(order_of_headers, headers) do
    case fetch_keys(order_of_headers, headers) do
      {:ok, ordered_headers} -> {:ok, compose_signing_string(ordered_headers)}
      {:error, reason} -> {:error, reason}
    end
  end

  def compose_signing_string(ordered_headers) do
    ordered_headers
    |> Enum.map(fn({k, v}) -> "#{k}: #{v}" end)
    |> Enum.join("\n")
  end

  def decode_key(key) do
    [key_entry] = :public_key.pem_decode(key)
    :public_key.pem_entry_decode(key_entry)
  end

  def encryption_type(decoded_key) do
    case decoded_key do
      {:RSAPublicKey, _, _} ->
        :rsa
      {{:ECPoint, _}, {:namedCurve, _curve_tuple}} ->
        # NOTE we accept all types of EC curves and treat them all the same.
        # There could be more strict checking on `curve_tuple` (e.g. for secp256r1)
        :ec
    end
  end

  def generate_salt do
    :crypto.strong_rand_bytes(64) |> Base.encode64
  end

  # What is the specification for this?
  def key_id(key) do
    key
    |> String.replace(~r/\r|\n/, "")
    |> hash_key
    |> Base.encode16(case: :lower)
    |> String.replace(~r/\w{2}(?!$)/, "\\0:")
  end

  defp hash_key(key) do
    :crypto.hash(:md5, key)
  end

  defp fetch_keys(collection, keys) do
    collection = for {k, v} <- collection, do: {k, v}
    do_fetch_keys(collection, keys, [])
  end

  defp do_fetch_keys(_collection, [], progress) do
    {:ok, Enum.reverse(progress)}
  end
  defp do_fetch_keys(collection, [key | rest], progress) do
    key = "#{key}"
    case List.keyfind(collection, key, 0) do
      {key, value} ->
        do_fetch_keys(collection, rest, [{key, value} | progress])
      nil ->
        {:error, {:missing_key, key}}
    end
  end
end
