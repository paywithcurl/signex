defmodule SignEx.Algorithm do
  @moduledoc """
    A `SignEx.Algorithm` struct contains all the information needed to deal with signature encryption and digest
  """

  @enforce_keys [:digest]
  defstruct [:encryption, :digest]

  defimpl String.Chars, for: SignEx.Algorithm do
    def to_string(alg), do: "#{alg.encryption}-#{alg.digest}"
  end

  @available [
        {:ec, :sha256},
        {:ec, :sha384},
        {:ec, :sha512},
        {:rsa, :sha256},
        {:rsa, :sha384},
        {:rsa, :sha512},
      ]

  @allowed_strings(
    @available
    |> Enum.map(&(to_string(elem(&1,0)) <> "-" <> to_string(elem(&1, 1))))
  )

  @available_digests [:sha256, :sha384, :sha512]
  @doc """
  List of available algorithms where each element is SignEx.Algorithm struct
  """
  defmacro available do
    quote do
      unquote(@available)
      |> Enum.map(fn({encryption, digest}) ->
        %SignEx.Algorithm{encryption: encryption, digest: digest}
      end)
    end
  end

  @doc """
  Return list of supported digest algorithms
  """
  def available_digests, do: @available_digests

  @doc """
  List of allowed algorithm string where each element is in format 'encryption-digest'
  """
  def allowed_strings, do: @allowed_strings

  @doc """
  Returns value of digest function to be used for generation signature digest and message digest
  """
  def default_digest do
    :sha512
  end

  @doc """
  Check if given digest string is allowd in SignEx
  """
  def allowed_digest?(digest_str) do
    Enum.any?(@available_digests, fn(digest) -> to_string(digest) == digest_str end)
  end

  @doc """
  Creates SignEx.Algorithm struct from valid algorithm string
  """
  def new(algorithm_str) do
    unless algorithm_str in allowed_strings() do
      raise "unknown algorithm string #{algorithm_str}"
    end
    [encryption, digest] = String.split(algorithm_str, "-")
    %__MODULE__{encryption: String.to_atom(encryption), digest: String.to_atom(digest)}
  end

  @doc """
  Returns digest in more readable form.
  """
  def humanize_digest(%__MODULE__{digest: digest}) do
    humanize_digest(digest)
  end

  def humanize_digest(digest) do
    digest
    |> to_string
    |> String.replace(~r/([a-zA-Z]+)(\d+)/, "\\1-\\2")
    |> String.upcase
  end
end
