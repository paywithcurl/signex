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
    case original_digest(hash_message(message, attrs["salt"]), attrs["signature"], public_key) do
      true -> :ok
      {:error, reason} -> {:error, reason}
      _ -> {:error, "Message doesn't match signature"}
    end
  end

  defp original_digest(message, signature, public_key) do
    try do
      {:ok, encrypted_digest} = Base.decode64(signature)
      :public_key.verify(message, :sha512, encrypted_digest, decode_key(public_key))
    rescue
      _ -> {:error, "invalid public key"}
    catch
      _ -> {:error, "invalid public key"}
    end
  end
end
