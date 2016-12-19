defmodule SignEx.Signer do
  import SignEx.Helper

  @key_types %{
    RSAPrivateKey: "rsa-sha512",
    ECPrivateKey: "ec-sha512"
  }

  def sign(message, private_key) do
    message_str = Poison.encode!(message)
    {:ok, "Signature #{signature_for(%{message: message_str, key: private_key})}", message_str}
  end

  defp signature_for(%{message: message, key: key}) do
    salt = generate_salt
    %{
      key_id: key_id(key),
      algorithm: algorithm_from_key(key),
      salt: salt,
      signature: salted_signature(%{message: message, salt: salt, key: key})
    }
    |> Enum.map(fn(pair) -> ~s(#{elem(pair, 0)}=#{elem(pair, 1)}) end)
    |> Enum.join(",")
  end

  defp salted_signature(%{message: message, salt: salt, key: key}) do
    hash_message(message, salt)
    |> sign_message(key)
    |> Base.encode64
  end

  defp sign_message(message, key) do
    :public_key.sign(message, :sha512, decoded_pem_entry(key))
  end

  defp decoded_pem_entry(key) do
    decode_pem(key)
    |> :public_key.pem_entry_decode
  end

  defp algorithm_from_key(key) do
    key_type = decode_pem(key)
    |> elem(0)
    Map.get(@key_types, key_type)
  end

  defp decode_pem(key) do
    case :public_key.pem_decode(key) do
      [_, key_entry] -> key_entry
      [key_entry] -> key_entry
      key_entry -> raise("unknown key type #{inspect key_entry}")
    end
  end
end
