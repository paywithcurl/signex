defmodule SignEx.Parameters do
  defstruct [:key_id, :algorithm, :headers, :signature]

  def to_string(%__MODULE__{
    key_id: key_id,
    algorithm: algorithm,
    headers: headers,
    signature: signature
    }) do
      headers = Enum.join(headers, " ")
     {:ok, "key_id=\"#{key_id}\",algorithm=\"#{algorithm}\",headers=\"#{headers}\",signature=\"#{signature}\""}
  end

  
end
