# typed: false
# frozen_string_literal: true

class Dcert < Formula
  desc "TLS certificate decoder and HTTPS chain inspector"
  homepage "https://github.com/SCGIS-Wales/dcert"
  url "https://github.com/SCGIS-Wales/dcert.git",
      tag:      "v0.1.1"
  head "https://github.com/SCGIS-Wales/dcert.git", branch: "main"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: ".")
  end

  test do
    # Basic smoke test: binary exists and reports a version string
    out = shell_output("#{bin}/dcert --version")
    assert_match "dcert", out
  end
end
