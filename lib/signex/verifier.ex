defmodule SignEx.Verifier do
  import SignEx.Helper

  def verify(message, signature, public_key) do
    signature_attrs = signature_params(signature)
    {:ok, encrypted_digest} = Base.decode64(signature_attrs["signature"])
    digest = :public_key.decrypt_public(encrypted_digest, decode_key(public_key))
    case hash_message(message, signature_attrs["salt"]) == digest do
      true -> :ok
      false -> {:error, "Message doesn't match signature"}
    end
  end
end
