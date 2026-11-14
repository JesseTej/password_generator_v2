# PasswordGen

A small GTK4 desktop app, written in Python, that generates random passwords and stores them in a local vault encrypted with a master password.

![lock icon](lock-41168_1280.png)

## Features

- Generate passwords of any length from digits, letters and/or symbols, using Python's cryptographically secure `secrets` module
- Copy the generated password to the clipboard
- Save a password together with a service name and username to an encrypted vault
- View every saved entry once the vault is unlocked
- Lock the vault so the master password has to be entered again

## How the vault works

When the app starts it asks for a master password. (The dialog calls it a "Sudo PassWord", but it is not your system password. It is a password you choose for the vault.)

- A 256-bit key is derived from the master password with PBKDF2-HMAC-SHA256 (390,000 iterations) and a random 16-byte salt.
- Entries are stored as JSON and encrypted with [Fernet](https://cryptography.io/en/latest/fernet/) (AES-128-CBC + HMAC-SHA256).
- Files are kept in `~/.local/share/passwordgen/`:
  - `vault.enc`: the encrypted entries
  - `vault.salt`: the salt for key derivation

The first password you enter becomes the master password. If you lose it, the vault cannot be recovered. Delete both files to start over.

Never commit vault, salt or key files to git. The `.gitignore` excludes `*.enc`, `*.salt` and `*.key`.

## Requirements

- Linux with GTK 4
- Python 3
- PyGObject (`python3-gi`, `gir1.2-gtk-4.0`)
- `cryptography`

On Debian/Ubuntu:

```bash
sudo apt install python3 python3-gi gir1.2-gtk-4.0 python3-cryptography
```

## Running from source

```bash
python3 passwordgen.py
```

## Installing the Debian package

A prebuilt package is included:

```bash
sudo apt install ./passwordgen.deb
```

Then launch **PasswordGen** from your application menu, or run `passwordgen` in a terminal.

To rebuild the package from the `passwordgen/` tree:

```bash
cp passwordgen.py passwordgen/usr/bin/passwordgen
chmod 755 passwordgen/usr/bin/passwordgen passwordgen/DEBIAN/postinst
dpkg-deb --build passwordgen
```

## Repository layout

| Path | Description |
| --- | --- |
| `passwordgen.py` | Current version of the app |
| `password_generator.py` | Earliest version: generator only, no vault |
| `password_generator2.py`, `password_generator3.py` | Intermediate versions that store the vault in the working directory |
| `passwordgen/` | Debian package source (`DEBIAN/` control files, binary, `.desktop` entry, icon) |
| `passwordgen.deb` | Built Debian package |
| `lock-41168_1280.png` | App icon source image |

## Known limitations

- Saving an entry for a service that already exists overwrites it.
- Saved passwords are shown in plain text in the "Saved Passwords" window.
