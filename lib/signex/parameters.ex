defmodule SignEx.Parameters do
  @moduledoc """
    A `SignEx.Parameters` struct contains all the information needed to reconstruct the signature of a message.
  """

  require Logger

  defstruct [:key_id, :algorithm, :headers, :signature]

  def to_string(params) do
    Logger.warn("Depreciated: Use `SignEx.Parameters.serialize`")
    serialize(params)
  end

  @doc """
  Serialize parameters as a HTTP signature header value
  """
  def serialize(%__MODULE__{
    key_id: key_id,
    algorithm: algorithm,
    headers: headers,
    signature: signature
    }) do
      headers = Enum.join(headers, " ")
     {:ok, "key_id=\"#{key_id}\",algorithm=\"#{algorithm}\",headers=\"#{headers}\",signature=\"#{signature}\""}

  end

  @parameters_pattern ~r/^key_id="(?<key_id>[^"]*)",algorithm="(?<algorithm>[^"]*)",headers="(?<headers>[^"]*)",signature="(?<signature>[^"]*)"$/

  @doc """
  Parse a parameters string serialized as a HTTP signature header.
  """
  def parse(serialized_parameters) do
    %{
      "key_id" => key_id,
      "algorithm" => algorithm, # = "rsa-sha512", # assume this signature so we can assume signature needs base64 decoding
      "headers" => headers,
      "signature" => signature,
    } = Regex.named_captures(@parameters_pattern, serialized_parameters)
    {:ok, %SignEx.Parameters{
      key_id: key_id,
      algorithm: algorithm,
      headers: headers |> String.split(" "),
      signature: signature
      }}
  end
end
