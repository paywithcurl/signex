defmodule SignEx.ParametersTest do
  use ExUnit.Case

  test "Serialized signature parameters can be recovered" do
    parameters = %SignEx.Parameters{
      key_id: "my-key-id",
      algorithm: "rsa-sha512",
      headers: ["host", "digest"],
      signature: "my-signature"
    }
    {:ok, str} = SignEx.Parameters.serialize(parameters)
    assert {:ok, parameters} == SignEx.Parameters.parse(str)
  end
end
