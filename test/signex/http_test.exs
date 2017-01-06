defmodule SignEx.HTTPTest do
  use ExUnit.Case
  import SignEx.HTTP

  doctest SignEx.HTTP

  @request_headers [
    {"host", "example.org"},
    {"date", "Tue, 07 Jun 2014 20:51:35 GMT"},
    {"content-type", "application/json"}
  ]

  test "default signature string is to use just the date header" do
    {:ok, str} = signature_string(@request_headers)
    assert "date: Tue, 07 Jun 2014 20:51:35 GMT" == str
  end

  test "can specify list of headers to use for generating signature_string" do
    {:ok, str} = signature_string(@request_headers, headers: [:host, :"content-type"])
    assert "host: example.org\ncontent-type: application/json" == str
  end

  test "fails is a required headers is not found" do
    assert = {:error, {:missing_key, "foo"}} = signature_string(@request_headers, headers: [:foo])
  end

  test "fails if no keys are specified" do
    assert = {:error, :no_headers_specified} = signature_string(@request_headers, headers: [])
  end

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
    assert {:ok, parameters} == SignEx.Parameters.parse(str)
  end

  test "walk through digest" do
    digest_header = SignEx.HTTP.digest_header_for("Hello")
    assert true == SignEx.HTTP.check_digest_header(digest_header, "Hello")
    assert false == SignEx.HTTP.check_digest_header(digest_header, "Other")
  end
end
