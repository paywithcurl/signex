defmodule SignEx.Signer do
  import SignEx.Helper

  def sign(message, private_key) do
    message_str = Poison.encode!(message)
    {:ok, "Signature #{signature_for(%{message: message_str, key: private_key})}", message_str}
  end

  defp signature_for(%{message: message, key: key}) do
    salt = generate_salt
    %{
      key_id: key_id(key),
      algorithm: "rsa-sha512",
      salt: salt,
      signature: salted_signature(%{message: message, salt: salt, key: key})
    }
    |> Enum.map(fn(pair) -> ~s(#{elem(pair, 0)}=#{elem(pair, 1)}) end)
    |> Enum.join(",")
  end

  defp salted_signature(%{message: message, salt: salt, key: key}) do
    hash_message(message, salt)
    |> :public_key.encrypt_private(decode_key(key))
    |> Base.encode64
  end

  defmacro __using__(_) do
    quote do
      alias SignEx.Signer

      def sign(message, private_key) do
        Signer.sign(message, private_key)
      end
    end
  end
end
