defmodule SignEx.HelperTest do
  use ExUnit.Case
  import SignEx.Helper

  test "composing a signing string from a single header" do
    headers = [{"host", "example.org"}]
    assert "host: example.org" == compose_signing_string(headers)
  end

  test "composing a signing string from multiple headers" do
    headers = [{"host", "example.org"}, {"content-type", "application/json"}]
    assert "host: example.org\ncontent-type: application/json" == compose_signing_string(headers)
  end
end
