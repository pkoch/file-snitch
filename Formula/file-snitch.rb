class FileSnitch < Formula
  desc "Guarded FUSE mounts for a user's secret-bearing files"
  homepage "https://github.com/pkoch/file-snitch"
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

      On macOS, install macFUSE separately before building or running
      file-snitch.

      The current authorization frontend is still a TTY agent. For a
      real prompt flow, run these in separate terminals:

        file-snitch agent --foreground
        file-snitch run prompt --foreground

      Background user services are intentionally deferred until the
      agent has a non-interactive frontend.
    EOS
  end

  test do
    output = shell_output("#{bin}/file-snitch help 2>&1")
    assert_match "file-snitch run", output
    assert_match "file-snitch agent", output
  end
end
