defmodule SignEx.Signer do
  alias SignEx.Algorithm
  import SignEx.Helper

  def sign(data, %{public_key: public_key, private_key: private_key}) do
    algorithm = algorithm_from_key(decode_pem(private_key))
    signing_string = compose_signing_string(data)
    signature = sign_message(signing_string, private_key, algorithm.digest)
    %SignEx.Parameters{
      key_id: key_id(public_key),
      algorithm: algorithm |> to_string(),
      headers: data |> Enum.map(fn({k, _v}) -> k end),
      signature: signature
    }
  end

  def algorithm_from_key({key_type, _, _}) do
    encryption = key_type
    |> to_string
    |> String.replace("PrivateKey", "")
    |> String.downcase
    %Algorithm{encryption: encryption, digest: Algorithm.default_digest()}
  end

  def sign_message(message, private_key, digest) do
    :public_key.sign(message, digest, decoded_pem_entry(private_key)) |> Base.encode64()
  end

  defp decoded_pem_entry(private_key) do
    decode_pem(private_key)
    |> :public_key.pem_entry_decode
  end

  defp decode_pem(private_key) do
    case :public_key.pem_decode(private_key) do
      [_, key_entry] -> key_entry
      [key_entry] -> key_entry
      key_entry -> raise("unknown key type #{inspect key_entry}")
    end
  end
end
