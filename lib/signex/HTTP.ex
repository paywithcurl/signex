defmodule SignEx.HTTP do
  @moduledoc """
  Verify the integrity of HTTP requests.

  `SignEx.HTTP` validates the integrity of HTTP requests by checking digest and signature.
  The digest header contains the digest of the request body, useing a configurable hash algorithm.
  The authorization header contains a signature and parameters that secure the request headers.

  *NOTE the signature will sign a subset of the headers,
  It is required for the digest header to be in this list so guarantee the integrity of the whole request.*

  - [Specification for the contents of the digest header](https://tools.ietf.org/html/rfc3230)
  - [Sepcification for signing HTTP Messages](https://tools.ietf.org/html/draft-cavage-http-signatures-05)

  ## Examples

      # iex> signature_string([{"date", "Tue, 07 Jun 2014 20:51:35 GMT"}])
      # "date: Tue, 07 Jun 2014 20:51:35 GMT"
  """

  @doc """
  Create a signature header string for a list of headers

  Will sign all headers passed in but has no knowledge of path psudo header.
  """
  def signature_header_for(headers, keypair) do
    parameters = SignEx.Signer.sign(headers, keypair)
    {:ok, parameters_string} = SignEx.Parameters.to_string(parameters)
    "Signature " <> parameters_string
  end

  @parameters_pattern ~r/^key_id="(?<key_id>[^"]*)",algorithm="(?<algorithm>[^"]*)",headers="(?<headers>[^"]*)",signature="(?<signature>[^"]*)"$/

  def parse_parameters(str) do
    %{
      "key_id" => key_id,
      "algorithm" => algorithm # = "rsa-sha512", # assume this signature so we can assume signature needs base64 decoding
      "headers" => headers,
      "signature" => signature,
    } = Regex.named_captures(@parameters_pattern, str)
    {:ok, %SignEx.Parameters{
      key_id: key_id,
      algorithm: algorithm,
      headers: headers |> String.split(" "),
      signature: signature
      }}
  end
end
