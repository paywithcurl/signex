defmodule SignEx.HTTPTest do
  use ExUnit.Case
  import SignEx.HTTP

  doctest SignEx.HTTP
  # TODO consider handling path as a psudo header {"path", "get /foo"} {"(request-target)"}, "get /foo"

  test "signature parameters can be recovered from a header" do
    parameters = %SignEx.Parameters{
      key_id: "my-key-id",
      algorithm: "rsa-sha512",
      headers: ["host", "digest"],
      signature: "my-signature"
    }
    {:ok, str} = SignEx.Parameters.to_string(parameters)
    assert {:ok, parameters} == SignEx.HTTP.parse_parameters(str)
  end
end
