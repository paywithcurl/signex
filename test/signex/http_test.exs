defmodule SignEx.HTTPTest do
  use ExUnit.Case
  import SignEx.HTTP

  doctest SignEx.HTTP
  # TODO consider handling path as a psudo header {"path", "get /foo"} {"(request-target)"}, "get /foo"

  test "composing a signing string from a single header" do
    headers = [{"host", "example.org"}]
    assert "host: example.org" == compose_signing_string(headers)
  end

  test "composing a signing string from multiple headers" do
    headers = [{"host", "example.org"}, {"content-type", "application/json"}]
    assert "host: example.org\ncontent-type: application/json" == compose_signing_string(headers)
  end

  test "checking digest for some content" do
    header = digest_header_for("hello")
    assert check_digest_header(header, "hello")
    refute check_digest_header(header, "other")
  end

  test "checking digest for no content" do
    header = digest_header_for("")
    assert check_digest_header(header, "")
    refute check_digest_header(header, "other")
  end

  test "signature parameters can be recovered from a header" do
    parameters = %SignEx.Parameters{
      key_id: "my-key-id",
      algorithm: "rsa-sha256",
      headers: ["host", "digest"],
      signature: "my-signature"
    }
    {:ok, str} = SignEx.Parameters.to_string(parameters)
    assert {:ok, parameters} == SignEx.HTTP.parse_parameters(str)
  end

  test "walk through digest" do
    digest_header = SignEx.HTTP.digest_header_for("Hello")
    assert true == SignEx.HTTP.check_digest_header(digest_header, "Hello")
    assert false == SignEx.HTTP.check_digest_header(digest_header, "Other")
  end
end
