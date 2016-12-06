defmodule SignEx do
  require SignEx.Signer
  require SignEx.Verifier
  require SignEx.Helper

  def sign(message, private_key), do: SignEx.Signer.sign(message, private_key)
  def verify(message, signature, public_key), do: SignEx.Verifier.verify(message, signature, public_key)
  def signature_params(signature), do: SignEx.Helper.signature_params(signature)
end
