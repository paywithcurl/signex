defmodule SignEx.HTTP do
  @moduledoc """
  Sign HTTP requests

  ## Examples

      # iex> signature_string([{"date", "Tue, 07 Jun 2014 20:51:35 GMT"}])
      # "date: Tue, 07 Jun 2014 20:51:35 GMT"
  """
  @default_headers [:date]

  def lock(headers, keypair, opts \\ []) do
    {:ok, message} = signature_string(headers, opts)
    {:ok, signature} = sign_message(message, keypair)
    header = %{
      keyId: keypair.id,
      algorith: keypair.algorithm,
      headers: opts.headers,
      signature: signature
    }
  end
  # def lock(headers, body, keypair, opts) do
  #   {:ok, digest} = digest(body)
  #   lock(headers ++ [{"digest", digest}], keypair, opts)
  # end

  def sign_message(message, keypair) do
    # use the existing signer
  end

  def verify_signature(headers, key) do

  end

  def check_digest_header("SHA-256=" <> digest, message) do
    digest == digest_content(message)
  end

  def digest_header_for(body) do
    "SHA-256=" <> digest_content(body)
  end

  def digest_content(body) do
    :crypto.hash(:sha256, body)
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
          string = headers
          |> Enum.map(fn({k, v}) -> "#{k}: #{v}" end)
          |> Enum.join("\r\n") #might be \n required
          {:ok, string}
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
