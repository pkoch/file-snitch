class FileSnitch < Formula
  desc "Guarded FUSE mounts for a user's secret-bearing files"
  homepage "https://github.com/pkoch/file-snitch"
  # stable-release-start
  url "https://github.com/pkoch/file-snitch/releases/download/v0.1.4/file-snitch-0.1.4-source.tar.gz"
  sha256 "816bf09101608050f66cc5d194a997b6076cc56cfc58eaf3aaedd7a1a4392188"
  version "0.1.4"
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
