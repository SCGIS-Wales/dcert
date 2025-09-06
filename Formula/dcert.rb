class Dcert < Formula
  desc "CLI to decode and validate TLS certificates from PEM files"
  homepage "https://github.com/SCGIS-Wales/dcert"
  url "https://github.com/SCGIS-Wales/dcert/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_ME_WITH_TARBALL_SHA256"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/dcert --version")
    (testpath/"test.pem").write <<~EOS
      -----BEGIN CERTIFICATE-----
      MIIBgzCCASmgAwIBAgIUEdF2kB0=
      -----END CERTIFICATE-----
    EOS
    # Should not error, and will likely report no valid certs
    system "#{bin}/dcert", "test.pem", "--format", "json"
  end
end
