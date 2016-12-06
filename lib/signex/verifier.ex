defmodule SignEx.Verifier do
  import SignEx.Helper

  def verify(message, signature, public_key) do
    attrs = signature_params(signature)
    case attrs do
      %{"signature" => _, "salt" => _, "key_id" => _, "algorithm" => _} -> verify_with_atttributes(message, attrs, public_key)
      _ -> {:error, "invalid signature"}
    end
  end

  defp verify_with_atttributes(message, attrs, public_key) do

    case original_digest(attrs["signature"], public_key) do
      {:error, reason} -> {:error, reason}
      digest ->
        case hash_message(message, attrs["salt"]) == digest do
          true -> :ok
          false -> {:error, "Message doesn't match signature"}
        end
    end
  end

  defp original_digest(signature, public_key) do
    try do
      {:ok, encrypted_digest} = Base.decode64(signature)
      :public_key.decrypt_public(encrypted_digest, decode_key(public_key))
    rescue
      _ -> {:error, "invalid public key"}
    catch
      _ -> {:error, "invalid public key"}
    end
  end
end
