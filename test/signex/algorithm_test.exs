defmodule SignEx.AlgorithmTest do
  use ExUnit.Case
  require SignEx.Algorithm
  alias SignEx.Algorithm

  test "list all available algorithms" do
    assert length(Algorithm.available()) > 0
    for alg <- Algorithm.available() do
      assert %Algorithm{} = alg
    end
  end

  test "list all allowed algorithm strings" do
    assert length(Algorithm.allowed_strings()) > 0
    for alg_str <- Algorithm.allowed_strings() do
      assert alg_str =~ ~r/\w+-\w{3}\d{3}/
    end
  end

  test "struct from string" do
    assert Algorithm.new("ec-sha512") == %Algorithm{encryption: :ec, digest: :sha512}
  end

  test "only create struct from string when one of valid " do
    assert_raise RuntimeError, fn ->
      Algorithm.new("des-sha1")
    end
  end

  test "takes algorithm struct and humanizes digest" do
    assert Algorithm.humanize_digest(%Algorithm{digest: :sha512}) == "SHA-512"
  end

  test "takes digest and humanizes" do
    assert Algorithm.humanize_digest(:sha122) == "SHA-122"
  end

  test "check if digest algorithm is valid" do
    assert Algorithm.allowed_digest?("sha512")
    refute Algorithm.allowed_digest?("sha123")
  end
end
