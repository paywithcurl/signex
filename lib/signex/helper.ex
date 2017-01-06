defmodule SignEx.Helper do

  def compose_signing_string(data) do
    data
    |> Enum.map(fn({k, v}) -> "#{k}: #{v}" end)
    |> Enum.join("\n")
  end

  def decode_key(key) do
    [key_entry] = :public_key.pem_decode(key)
    :public_key.pem_entry_decode(key_entry)
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
