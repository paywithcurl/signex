defmodule SignEx do
  require SignEx.Signer
  require SignEx.Verifier
  require SignEx.Helper

  def sign(message, private_key, public_key), do: SignEx.Signer.sign(message, private_key, public_key)
  def verify(message, signature, public_key), do: SignEx.Verifier.verify(message, signature, public_key)
  def signature_params(signature), do: SignEx.Helper.signature_params(signature)

  def verify_signing(headers, params = %SignEx.Parameters{}, keystore) do
    "rsa-sha256" = params.algorithm
    {:ok, signature} = Base.decode64(params.signature)
    signing_string = params.headers
    |> Enum.map(fn(host) -> List.keyfind(headers, host, 0) end)
    |> SignEx.HTTP.compose_signing_string
    # TODO create a behaviour module for the keystore to return public_key
    public_key = keystore
    :public_key.verify(signing_string, :sha512, signature, SignEx.Helper.decode_key(public_key))
  end
end
