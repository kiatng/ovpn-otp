# ovpn-otp

ovpn-otp connects you to an OpenVPN server that wants your 6-digit authenticator code typed after your password, and it gives that code its own box so you can see what you typed.

It works with Sophos Firewall SSL VPN and with any other OpenVPN server that expects the code appended to the password. It runs on Windows and Linux, as a small desktop window (`ovpn-otp-gui`) and as a command-line tool (`ovpn-otp`) for scripts and agents.

![The ovpn-otp window, connected: login on the left, status, traffic and the connection timeline on the right](docs/window-connected.png)

> [!NOTE]
> ovpn-otp is an independent open-source project. It is not affiliated with, endorsed by or connected to Sophos or OpenVPN Inc. It uses the free OpenVPN community program to make the actual connection.

## Why

Many firewall VPNs ask for "password followed by your 2FA code" in one masked password box. You type `mypassword123456`, see only dots, and when the login fails you cannot tell whether the password or the code was wrong. ovpn-otp fixes that, and adds a few things the usual clients leave out:

- **Saved login.** Your user name and password are kept in the credential store of your operating system (Windows Credential Manager, or the desktop keyring on Linux), never in a file.
- **A separate, visible code box.** You type the 6 digits on their own, in plain sight, and ovpn-otp appends them to the password for you.
- **See what is going on.** A live timeline of the connection steps, bytes in and out with the current speed, how long ago data last arrived, your tunnel address, the routes and DNS servers the server sent, an optional check that a host behind the VPN answers (with the round-trip time), a full log with a level filter, and the complete conversation with OpenVPN, with secrets hidden.
- **Keep-alive and reconnect.** Keep-alive pings detect a dead link, and ovpn-otp reconnects by itself with a growing wait between tries. Because the server wants a fresh code after a real drop, ovpn-otp asks you for one.
- **One settings file for all your machines.** The settings hold no secrets, so you can keep them in a synced folder or a private git repository and use the same file on your Windows PC and your Linux laptop.

## How it works

ovpn-otp does not implement the VPN itself. It starts the standard `openvpn` program and steers it through the OpenVPN management interface, a text channel on `127.0.0.1` that OpenVPN offers for exactly this purpose. When the server asks for a login, OpenVPN asks ovpn-otp, and ovpn-otp answers with your saved user name and `password + code`.

```
 you ── ovpn-otp window or CLI ──(management interface, 127.0.0.1)── openvpn ──(VPN)── server
```

Because the real work is done by OpenVPN, your connection is exactly as secure and compatible as it is with any other OpenVPN client.

## Install

### Windows

1. Install the **OpenVPN community client**, version 2.6 or newer, from <https://openvpn.net/community-downloads/> with the default options. The defaults include the "OpenVPN Interactive Service", which lets ovpn-otp start OpenVPN without admin rights. (OpenVPN Connect, the other OpenVPN app, cannot be used: it has no way for another program to drive it.)
2. Make sure your Windows user is in the **OpenVPN Administrators** group. The installer adds the user who ran it; to add another user, open *Computer Management → Local Users and Groups → Groups → OpenVPN Administrators*, add the user, then sign out and in again. Members of this group may run their own VPN profiles through the service.
3. Download `ovpn-otp-<version>-x86_64-pc-windows-msvc.zip` from the [releases page](https://github.com/kiatng/ovpn-otp/releases), unzip it anywhere, and start `ovpn-otp-gui.exe`.

### Linux (Arch, Omarchy, Debian, Ubuntu, ...)

1. Install OpenVPN with your package manager:

   ```sh
   sudo pacman -S openvpn        # Arch, Omarchy
   sudo apt install openvpn      # Debian, Ubuntu
   ```

2. Download `ovpn-otp-<version>-x86_64-unknown-linux-gnu.tar.gz` from the [releases page](https://github.com/kiatng/ovpn-otp/releases) and put the two programs on your path:

   ```sh
   tar xzf ovpn-otp-*-x86_64-unknown-linux-gnu.tar.gz
   install -m 755 ovpn-otp-*/ovpn-otp ovpn-otp-*/ovpn-otp-gui ~/.local/bin/
   ```

3. Give OpenVPN the right to create the tunnel, as described in [Linux: let openvpn create the tunnel](#linux-let-openvpn-create-the-tunnel). **Do not run the window itself as root**; only OpenVPN needs the extra rights.

To build from source instead, install Rust and run `cargo build --release`; the programs land in `target/release/`.

## First connect

You need your VPN profile, a `.ovpn` file. On a Sophos Firewall you download it from the user portal, in the SSL VPN section; other servers have a similar download. If you already imported it into another client, download it again, because ovpn-otp needs the file itself.

1. Put the profile somewhere you like, for example next to your settings file.
2. Start `ovpn-otp-gui`. It opens on the **Settings** tab because there is no profile yet. Enter the path to the `.ovpn` file and click **Save settings**.
3. On the left, enter your user name and password. Leave **Remember user name and password** ticked to keep them in the credential store.
4. Open your authenticator app, type the 6-digit code into **Authenticator code**, and press Enter or click **Connect**.

Notice what you did **not** have to do: you never glued the code onto the password, and next time you only type the code.

From the command line the same steps look like this:

```sh
ovpn-otp config init --profile ~/vpn/work.ovpn --name work   # once
ovpn-otp login                                               # once: saves user name and password
ovpn-otp connect                                             # asks for the code, shows each step
```

`connect` stays in the foreground and prints each connection step; press Ctrl+C to disconnect. You may now be wondering how to check on it from another terminal, or how a script gives it a code. Both are covered in [Command line](#command-line) below.

## The window

The left side holds the login: user name, password (hidden, with a **Show** toggle), the **Remember** box, and the code box. The code box takes digits only and counts them ("4 of 6 digits"), so a short or mistyped code is caught before it reaches the server.

The right side shows what is going on:

| Area | What it shows |
| --- | --- |
| Status | The overall state (Connecting, Connected, Waiting for your code, Reconnecting, ...) and what OpenVPN itself reports. |
| Server, Tunnel address | The server in use and the address you got inside the VPN. |
| Received, Sent | Total bytes and the speed over the last second. |
| Connected for, Last data received | How long the connection has been up, and how many seconds ago anything arrived. A number that keeps growing means the link has gone quiet. |
| Reach check | The answer time from a host behind the VPN, when you set one in Settings. |
| Routes, DNS | What the server told your machine to send through the VPN. |
| Timeline | Every connection step (CONNECTING, WAIT, AUTH, GET_CONFIG, ASSIGN_IP, ADD_ROUTES, CONNECTED, RECONNECTING, EXITING) with its time. |
| Log | The OpenVPN log and messages from ovpn-otp, with a filter for warnings and errors. |
| Wire | Every line exchanged with OpenVPN on the management interface. Passwords, codes and session tokens show as `********`. |

**Copy diagnostics** at the bottom puts a troubleshooting report on the clipboard: versions, status, settings, timeline, log and wire transcript. Your password never appears in it, and your user name is replaced with `<user>`.

## Keep-alive and reconnect

Two settings make OpenVPN notice a dead link: it sends a keep-alive **ping** every 10 seconds, and when nothing arrives for 60 seconds it **restarts** the connection. Some servers send their own values, which then take priority.

When a connection drops, ovpn-otp waits a little and tries again: first 2 seconds, then 4, 8 and so on, up to 60 seconds. The server needs a fresh code for the new login, so the window comes to the front, the code box turns orange and says "Reconnecting: enter a new code". In the terminal, `connect` prints a prompt; type the code and press Enter. A code that is more than 90 seconds old is not used, because the server would reject it.

![After a drop, the window asks for a new code](docs/window-new-code.png)

ovpn-otp never stores or generates your authenticator secret. The code always comes from your authenticator app.

> [!TIP]
> Turn off **Reconnect automatically** in Settings if you would rather have ovpn-otp stop after a drop.

## Sharing settings between machines

Everything except your login lives in one settings file, `settings.toml`. ovpn-otp looks for it in this order:

1. the `--config FILE` option (for the window: `ovpn-otp-gui FILE`);
2. the `OVPN_OTP_CONFIG` environment variable;
3. the default place: `%APPDATA%\ovpn-otp\config\settings.toml` on Windows, `~/.config/ovpn-otp/settings.toml` on Linux.

Run `ovpn-otp config path` to see which file is in use.

To share the settings, put `settings.toml` and your `.ovpn` profile together in a folder that both machines see, such as a synced folder (Syncthing, OneDrive, Dropbox) or a **private** git repository. Write the profile path relative to the settings file (`path = "work.ovpn"`), so it works on both machines. Then point each machine at the file:

```powershell
# Windows (PowerShell), once:
[Environment]::SetEnvironmentVariable("OVPN_OTP_CONFIG", "$env:USERPROFILE\Sync\vpn\settings.toml", "User")
```

```sh
# Linux, in ~/.bashrc or ~/.profile:
export OVPN_OTP_CONFIG=~/Sync/vpn/settings.toml
```

On each machine you save the login once (`ovpn-otp login`, or tick **Remember** in the window), because the credential store is per machine. Settings that differ between Windows and Linux, such as where `openvpn` is, live in their own `[openvpn.windows]` and `[openvpn.linux]` sections, so one file serves both.

> [!WARNING]
> The `.ovpn` profile contains the certificate for your VPN and sometimes a private key. Share it only through a private folder or repository, never a public one.

## Settings

Every option, with its default. The same list, with comments, is in [`examples/settings.toml`](examples/settings.toml).

| Option | Default | What it does |
| --- | --- | --- |
| `name` | `"default"` | A short name for the connection. The saved login is stored under this name. |
| `profile.path` | | Path to the `.ovpn` profile, relative to the settings file. |
| `profile.inline` | | The profile text itself, instead of `path`. |
| `profile.remote` | | `host:port` to use instead of the `remote` line in the profile. |
| `keepalive.ping` | `10` | Seconds between keep-alive pings. 0 uses the profile's value. |
| `keepalive.ping_restart` | `60` | Seconds without anything from the server before OpenVPN restarts the connection. 0 uses the profile's value. |
| `keepalive.auto_reconnect` | `true` | Reconnect by itself after a drop (asks for a new code). |
| `keepalive.backoff_initial` | `2` | Seconds to wait before the first reconnect try. Doubles on each try. |
| `keepalive.backoff_max` | `60` | Longest wait between tries, in seconds. |
| `check.host` | | A host behind the VPN to check while connected: `10.0.0.1` uses ping, `10.0.0.1:443` opens a TCP connection. Empty turns the check off. |
| `check.interval` | `15` | Seconds between checks. |
| `code.digits` | `6` | Digits in your code. 0 accepts any length. |
| `openvpn.extra_options` | `[]` | Extra OpenVPN options added after the profile, one per item, such as `"verb 4"`. |
| `openvpn.verb` | `3` | How much OpenVPN logs, from 1 (little) to 6 (a lot). |
| `openvpn.windows.path` | found automatically | Where `openvpn.exe` is. |
| `openvpn.windows.launch` | `"auto"` | `"service"` starts OpenVPN through the interactive service (no admin rights), `"direct"` runs `openvpn.exe` yourself (needs an admin window), `"auto"` uses the service when it is running. |
| `openvpn.linux.path` | found automatically | Where `openvpn` is. |
| `openvpn.linux.command_prefix` | `["sudo", "-n"]` | The command that gives OpenVPN network rights, put in front of `openvpn`. `[]` when it already has them. |

Before OpenVPN starts, ovpn-otp makes a private copy of your profile with a few changes: the login always comes from ovpn-otp, `auth-nocache` makes OpenVPN ask for a fresh login after a drop, your keep-alive values are added at the end, and the copy is deleted when the session ends. Your own `.ovpn` file is never changed.

## Command line

`ovpn-otp` does everything the window does. A session started by the window can also be checked and stopped from the command line, and the other way round.

| Command | What it does |
| --- | --- |
| `ovpn-otp connect` | Connect and stay connected until Ctrl+C. Asks for the code, or takes `--otp 123456`. |
| `ovpn-otp status` | Show the running session: state, server, address, traffic, last data, check, routes. `--json` prints everything as JSON. |
| `ovpn-otp logs` | Print the session log. `-f` keeps following it, `--wire` adds the management transcript, `-n 50` shows the last 50 lines. |
| `ovpn-otp disconnect` | Stop the running session. |
| `ovpn-otp login` / `logout` | Save or remove the user name and password in the credential store. |
| `ovpn-otp config path` / `show` / `init` | Show where the settings file is, print it, or create one for a profile. |
| `ovpn-otp diagnostics` | Print the troubleshooting report, with secrets removed. |
| `ovpn-otp doctor` | Check the settings, the profile, OpenVPN, the privileges and the saved login. |

For scripts and agents, `connect` can take everything without a prompt. Here a script passes the password on standard input (so it never shows in the process list) and the code as an option:

```sh
printf '%s\n' "$VPN_PASSWORD" | ovpn-otp connect --username alice --password-stdin --otp 123456 &
ovpn-otp status --json      # "phase": "Connected" once it is up
ovpn-otp disconnect
```

When the server later wants a new code, `connect` reads it from the next line of standard input. `connect` exits with code 0 after a normal disconnect, 1 when it failed, and 2 when the connection dropped with reconnect turned off.

There is no background service: whichever program started the session (the window or `connect`) runs it, and the other commands talk to it through small files in a private folder (`$XDG_RUNTIME_DIR/ovpn-otp` on Linux, `%LOCALAPPDATA%\ovpn-otp\data\run` on Windows; `OVPN_OTP_RUNTIME_DIR` overrides it).

## Linux: let openvpn create the tunnel

Creating a VPN tunnel and its routes needs network administrator rights, so OpenVPN must run with them while ovpn-otp itself runs as you. By default ovpn-otp starts OpenVPN through `sudo -n`, where `-n` means "fail instead of asking for a password" so the window never hangs on an invisible prompt. Pick one of these three ways:

**1. Allow sudo for openvpn without a password (simplest).** Create a sudo rule for your user:

```sh
echo "$USER ALL=(root) NOPASSWD: $(command -v openvpn)" | sudo tee /etc/sudoers.d/ovpn-otp
sudo chmod 440 /etc/sudoers.d/ovpn-otp
ovpn-otp doctor          # should say "sudo: openvpn may run without a password prompt"
```

> [!WARNING]
> An OpenVPN profile can run commands, so this rule effectively gives your user account root rights without a password. On a laptop only you use, that is usually acceptable; on a shared machine, prefer option 2.

**2. Ask for your password each time (pkexec).** Set `command_prefix = ["pkexec"]` under `[openvpn.linux]`. Your desktop then shows a password dialog at every connect and reconnect.

**3. Give the openvpn program the network right itself.** This avoids root altogether:

```sh
sudo setcap cap_net_admin+ep "$(command -v openvpn)"
```

and set `command_prefix = []`. Package updates remove this setting, so run the command again after updating OpenVPN. Scripts in the profile, such as DNS update scripts, then also run without root.

**DNS on Linux.** OpenVPN 2.6 does not change your DNS servers by itself, so names behind the VPN may not resolve. If you need them, add a DNS update script through `extra_options`. For example, with the `update-systemd-resolved` script installed for systemd-resolved:

```toml
[openvpn]
extra_options = ["script-security 2", "up /etc/openvpn/update-systemd-resolved", "down /etc/openvpn/update-systemd-resolved", "down-pre"]
```

OpenVPN 2.7 and newer handle DNS through their built-in `dns-updown` script.

## Troubleshooting

Start with `ovpn-otp doctor`, which checks each piece in turn. Then look at the **Log** and **Wire** tabs (or `ovpn-otp logs --wire`).

| What you see | What to do |
| --- | --- |
| "OpenVPN is not installed, or its interactive service is not running" (Windows) | Install the OpenVPN community client with its default options. In *Services*, check that "OpenVPN Interactive Service" is running. |
| "The service only runs configs from its own config folder" (Windows) | Add your user to the **OpenVPN Administrators** group, then sign out and in again. |
| "sudo wants a password" (Linux) | Follow [Linux: let openvpn create the tunnel](#linux-let-openvpn-create-the-tunnel). |
| "Cannot open TUN" or "Operation not permitted" | OpenVPN has no network rights; see the same section. |
| "Login rejected" | Check the code first: wait for a new code in your app and try again. If it keeps failing, re-enter your password (tick **Show** to check it) and save it again. |
| Connected, but nothing behind the VPN works | Look at **Routes**: the server decides what goes through the VPN. Set a **Reach check** host to see whether the VPN itself carries traffic. On Linux, see the DNS note above. |
| "Last data received" keeps growing | The link has gone quiet. OpenVPN restarts it after `ping_restart` seconds, and ovpn-otp asks you for a new code. |
| OpenVPN keeps running after ovpn-otp was force-closed | ovpn-otp stops OpenVPN when you disconnect or close the window, but a crash or a forced kill leaves it running. Stop it from Task Manager (Windows) or with `sudo pkill -f 'openvpn --config .*ovpn-otp'` (Linux), which matches only an OpenVPN started by ovpn-otp. |
| Cannot read the saved login (Linux) | ovpn-otp needs a keyring through the Secret Service, such as GNOME Keyring or KeePassXC. On a desktop without one, install `gnome-keyring`, or use `--username` with `--password-stdin`. |

When you ask for help, paste the output of **Copy diagnostics** or `ovpn-otp diagnostics`. Your password is never in it, but read it through before you post it publicly: it does contain the server address and the log.

## Security and privacy

- **Your password** is kept only in the OS credential store and in memory while connecting. It is never written to a file or a log; the management transcript shows `********` instead.
- **Your code** is used once and never stored.
- **The management interface** listens only on `127.0.0.1` and is protected by a random password that changes every time OpenVPN starts. That password reaches OpenVPN through a private file (Linux) or the interactive service (Windows), and the file is deleted when the session ends.
- **The private copy of your profile** is readable only by you and is deleted when the session ends.

## Development

The code is a Rust workspace with three crates:

- `crates/core`: the library. It holds the settings, the saved login, the profile changes, the management protocol parser and the session that logs in, watches and reconnects;
- `crates/cli`: the `ovpn-otp` command;
- `crates/gui`: the `ovpn-otp-gui` window (egui).

Here is how to run the tests:

```sh
cargo test --workspace            # unit tests, and session tests against a fake OpenVPN
tests/integration/run.sh          # a real OpenVPN server and client, Linux only
```

The integration test builds a throwaway certificate authority, starts an OpenVPN server whose login script accepts one test user with password + a fixed test code, and runs the library and the CLI against it. It proves connect, the state timeline, byte counts, the reach check, a server-side drop with reconnect and a fresh code, a rejected code, and disconnect. It runs inside a private network namespace, so it needs `openvpn`, `openssl` and `unshare` but no root, and it cannot touch your real network.

Not done yet, and welcome as contributions: macOS support, a tray icon, and automatic updates.

## License

MIT, see [LICENSE](LICENSE).
