class FileSnitch < Formula
  desc "Guarded FUSE mounts for a user's secret-bearing files"
  homepage "https://github.com/pkoch/file-snitch"
  # stable-release-start
  url "https://github.com/pkoch/file-snitch/releases/download/v0.1.6/file-snitch-0.1.6-source.tar.gz"
  sha256 "58ae2dd2893f923a94f19c58f9215b37804e92abb13064b60f874f52ec135a23"
  version "0.1.6"
  # stable-release-end
  head "https://github.com/pkoch/file-snitch.git", branch: "master"

  depends_on "pkgconf" => :build
  depends_on "zig" => :build
  depends_on "pass"

  def install
    system "zig", "build", *std_zig_args
  end

  def caveats
    <<~EOS
      file-snitch currently assumes:
        * a working `pass` setup
        * a usable GPG environment for `pass`
        * FUSE support installed outside Homebrew

      On macOS, install macFUSE separately before building or running.

      Prompting is handled by the local agent service. Bootstrap it
      manually with:

        file-snitch agent --foreground
        file-snitch run prompt --foreground

      The repo also ships per-user service helpers under `scripts/`
      for `launchd` and `systemd --user`.
    EOS
  end

  test do
    output = shell_output("#{bin}/file-snitch version 2>&1")
    assert_match "file-snitch", output
  end
end
