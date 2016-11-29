defmodule SignEx.Helper do
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
end
