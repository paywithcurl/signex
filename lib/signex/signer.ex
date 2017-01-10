defmodule SignEx.Signer do
  import SignEx.Helper

  @key_types %{
    RSAPrivateKey: "rsa-sha512",
    ECPrivateKey: "ec-sha512"
  }

  def sign(data, keypair) do
    signing_string = compose_signing_string(data)
    signature = sign_message(signing_string, keypair.private_key) |> Base.encode64
    %SignEx.Parameters{
      key_id: key_id(keypair.public_key),
      algorithm: "rsa-sha512",
      headers: data |> Enum.map(fn({k, _v}) -> k end),
      signature: signature
    }
  end

  def sign_message(message, private_key) do
    :public_key.sign(message, :sha512, decoded_pem_entry(private_key))
  end

  defp decoded_pem_entry(private_key) do
    decode_pem(private_key)
    |> :public_key.pem_entry_decode
  end

  defp algorithm_from_key(private_key) do
    key_type = decode_pem(private_key)
    |> elem(0)
    Map.get(@key_types, key_type)
  end

  defp decode_pem(private_key) do
    case :public_key.pem_decode(private_key) do
      [_, key_entry] -> key_entry
      [key_entry] -> key_entry
      key_entry -> raise("unknown key type #{inspect key_entry}")
    end
  end
end
