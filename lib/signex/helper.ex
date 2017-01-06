defmodule SignEx.Helper do

  def signature_params(signature) do
    try do
      Regex.replace(~r/^Signature /, signature, "")
      |> String.split(",")
      |> Enum.map(fn(attr) -> Regex.split(~r/=/, attr, [parts: 2]) end)
      |> Enum.reduce(%{}, fn
        ([key, value], result) -> Map.put(result, String.trim(key), value)
        (_, result) -> result
      end)
    rescue
      _ -> %{}
    catch
      _ -> %{}
    end
  end

  def hash_message(message, salt) do
    :crypto.hash(:sha512, message <> salt)
  end

  def decode_key(key) do
    [key_entry] = :public_key.pem_decode(key)
    :public_key.pem_entry_decode(key_entry)
  end

  def generate_salt do
    :crypto.strong_rand_bytes(64) |> Base.encode64
  end

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

  def fetch_keys(collection, keys) do
    # treat maps and keyword lists the same
    collection = for {k, v} <- collection, do: {k, v}
    do_fetch_keys(collection, keys, [])
  end

  def do_fetch_keys(_collection, [], progress) do
    {:ok, Enum.reverse(progress)}
  end
  def do_fetch_keys(collection, [key | rest], progress) do
    key = "#{key}"
    case List.keyfind(collection, key, 0) do
      {key, value} ->
        case do_fetch_keys(collection, rest, [{key, value} | progress]) do
          {:ok, result} ->
            {:ok, result}
          {:error, reason} ->
            {:error, reason}
        end
      nil ->
        {:error, {:missing_key, key}}
    end
  end
end
