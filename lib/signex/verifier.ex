defmodule SignEx.Verifier do
  import SignEx.Helper

  def verify(message, signature, public_key) do
    signature_attrs = signature_to_map(signature)
    {:ok, encrypted_digest} = Base.decode64(signature_attrs["signature"])
    digest = :public_key.decrypt_public(encrypted_digest, decode_key(public_key))
    case hash_message(message, signature_attrs["salt"]) == digest do
      true -> :ok
      false -> {:error, "Message doesn't match signature"}
    end
  end

  defp signature_to_map(signature) do
    Regex.replace(~r/^Signature /, signature, "")
    |> String.split(",")
    |> Enum.map(fn(attr) -> Regex.split(~r/=/, attr, [parts: 2]) end)
    |> Enum.reduce(%{}, fn([key, value], result) -> Map.put(result, String.trim(key), value) end)
  end

  defmacro __using__(_) do
    quote do
      alias SignEx.Verifier

      def verify(message, signature, private_key) do
        Verifier.verify(message, signature, private_key)
      end
    end
  end
end
