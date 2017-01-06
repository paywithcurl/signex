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
  @default_headers [:date]

  def digest_header_for(body) do
    "SHA-256=" <> Base.encode64(digest_content(body))
  end

  def digest_content(body) do
    :crypto.hash(:sha256, body)
  end

  def check_digest_header("SHA-256=" <> digest, message) do
    {:ok, digest} = Base.decode64(digest)
    digest == digest_content(message)
  end

  def compose_signing_string(headers) do
    headers
    |> Enum.map(fn({k, v}) -> "#{k}: #{v}" end)
    |> Enum.join("\n")
  end

  def signature_header_for(headers, keypair) do
    signing_string = SignEx.HTTP.compose_signing_string(headers)
    signature = SignEx.Signer.sign_message(signing_string, keypair.private_key) |> Base.encode64
    parameters = %SignEx.Parameters{
      key_id: "my-id",
      algorithm: "rsa-sha256",
      headers: headers |> Enum.map(fn({k, _v}) -> k end),
      signature: signature
    }
    {:ok, parameters_string} = SignEx.Parameters.to_string(parameters)
    "Signature " <> parameters_string
  end

  # Any enum with tuple pairs should work.
  def signature_string(headers, opts \\ []) when is_list(headers) do
    signed_headers = Keyword.get(opts, :headers, @default_headers)
    if [] == signed_headers do
      {:error, :no_headers_specified}
    else
      fetch_signed_headers(signed_headers, headers)
      case fetch_signed_headers(signed_headers, headers) do
        {:ok, headers} ->
          {:ok, compose_signing_string(headers)}
        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  def fetch_signed_headers(signed_headers, headers) do
    do_fetch_signed_headers(signed_headers, headers, [])
  end

  def do_fetch_signed_headers([], headers, progress) do
    {:ok, Enum.reverse(progress)}
  end
  def do_fetch_signed_headers([next | rest], headers, progress) do
    next = "#{next}"
    case List.keyfind(headers, next, 0) do
      {key, value} ->
        case do_fetch_signed_headers(rest, headers, [{key, value} | progress]) do
          {:ok, result} ->
            {:ok, result}
        end
      nil ->
        {:error, {:missing_key, next}}
    end
  end
end
