# Install

## Prerequisites

File Snitch needs a working FUSE installation and an initialized `pass` store
with a GPG key that you can use to encrypt and decrypt entries.

| Platform | Requirements |
| --- | --- |
| macOS | Homebrew, macFUSE, `pass`, and GPG |
| Linux | Homebrew/Linuxbrew, distro FUSE 3, `pass`, and GPG; `zenity` for GUI prompts and user services |

On Debian/Ubuntu, install the FUSE runtime and build headers with:

```bash
sudo apt-get install -y fuse3 libfuse3-dev
```

FUSE is a separate system prerequisite; the File Snitch formula does not manage
it. The Linux GUI frontend also needs a graphical session where `zenity` can
open a dialog. Terminal prompting works without it.

## Install the binary

```bash
brew install pkoch/tap/file-snitch
file-snitch --version
pass ls >/dev/null
```

The formula lives in [pkoch/homebrew-tap](https://github.com/pkoch/homebrew-tap).
For unreleased `master` changes:

```bash
brew install --HEAD --build-from-source pkoch/tap/file-snitch
```

You can also download a binary tarball from
[GitHub Releases](https://github.com/pkoch/file-snitch/releases), extract it,
and put `file-snitch` on your `PATH`. Building from a checkout is covered in
[development](./development.md).

## First run

Use a disposable file to check enrollment, prompting, and restoration with your
real `pass` setup. The [demo](./demo.md) uses a fake store if you prefer that
first.

In your original terminal, create and enroll a file under your home directory:

```bash
example_file=$(mktemp "$HOME/file-snitch-example.XXXXXX")
printf 'File Snitch example\n' > "$example_file"
file-snitch enroll "$example_file"
```

Enrollment stores the contents under `pass:file-snitch/<object_id>` and removes
the original file. Keep this terminal open so `$example_file` remains set.

In a second terminal, start the agent. Choose one frontend:

```bash
file-snitch agent                              # terminal prompts
# file-snitch agent --frontend macos-ui        # macOS dialogs
# file-snitch agent --frontend linux-ui        # Linux dialogs via zenity
```

In a third terminal, start the daemon:

```bash
file-snitch run prompt
```

Both processes stay in the foreground. All three terminals must use the same
policy, store, and agent socket environment; see
[CLI defaults](./cli.md#paths-and-environment) if you have customized them.

After the daemon mounts the projection, return to the original terminal:

```bash
file-snitch status
cat "$example_file"
```

Choose **allow once** in the agent. The read should print `File Snitch example`.
To finish, leave the daemon running while you restore the file:

```bash
file-snitch unenroll "$example_file"
cat "$example_file"
rm "$example_file"
```

Stop the daemon and agent with Ctrl-C. You can now repeat the flow with a file
you want to guard, or set up [user services](./services.md) to run at login.

For missing files, failed prompts, or store errors, follow
[operations and troubleshooting](./operations.md).

## Shell completion

`file-snitch completion` generates scripts for bash, zsh, and fish. The
[completion reference](./cli.md#completion) gives installation commands.
