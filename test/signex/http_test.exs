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
    assert "host: example.org\r\ncontent-type: application/json" == str
  end

  test "fails is a required headers is not found" do
    assert = {:error, {:missing_key, "foo"}} = signature_string(@request_headers, headers: [:foo])
  end

  test "fails if no keys are specified" do
    assert = {:error, :no_headers_specified} = signature_string(@request_headers, headers: [])
  end

  # TODO consider handling path as a psudo header {"path", "get /foo"} {"(request-target)"}, "get /foo"

  test "walk through digest" do
    digest_header = SignEx.HTTP.digest_header_for("Hello")
    assert true == SignEx.HTTP.check_digest_header(digest_header, "Hello")
    assert false == SignEx.HTTP.check_digest_header(digest_header, "Other")
  end
end
