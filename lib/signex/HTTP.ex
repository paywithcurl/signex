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

  def sign(request = %{
    method: method,
    path: path,
    headers: headers,
    body: body
    }, keypair) do
      headers_to_sign = [request_target(request) | headers]
      |> Enum.into(%{})
      case SignEx.sign(body, headers_to_sign, keypair) do
        {:ok, {%{"digest" => digest}, signature_params}} ->
          {:ok, signature_string} = SignEx.Parameters.serialize(signature_params)
          headers = headers ++ [
            {"digest", digest},
            {"authorization", "Signature "<> signature_string}
          ]
          %{request | headers: headers}
      end
  end

  defp request_target(%{method: method, path: path}) do
    method = "#{method}" |> String.downcase
    {"(request-target)", "#{method} #{path}"}
  end

  require Logger

  def parse_parameters(str) do
    Logger.warn("Deprechiated: Use `SignEx.Parameters.parse`")
    SignEx.Parameters.parse(str)
  end
end
