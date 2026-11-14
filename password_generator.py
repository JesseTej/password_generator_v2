#!/usr/bin/env python3

import gi
import string
import secrets

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, Gio, Gdk, GLib

import json
from cryptography.fernet import Fernet


class PasswordGenerator(Gtk.Application):
# Iniate the length of the password    
    def __init__(self):
        super().__init__(application_id="org.example.PasswordGenerator")
        self.connect("activate", self.on_activate)
        self.window = None

# Design of the application
    def on_activate(self, app):
        if not self.window:
            self.window = Gtk.ApplicationWindow(application=self)
            self.window.set_title("GTK4 Password Generator")
            self.window.set_default_size(400, 250)

            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin_top=20, margin_bottom=20, margin_start=20, margin_end=20)
            self.window.set_child(box)

            self.length_entry = Gtk.Entry()
            self.length_entry.set_placeholder_text("Enter password length")
            box.append(self.length_entry)

            self.digits_check = Gtk.CheckButton(label="Include Digits")
            self.letters_check = Gtk.CheckButton(label="Include Letters")
            self.symbols_check = Gtk.CheckButton(label="Include Symbols")
            self.all_above_check = Gtk.CheckButton(label="Include All of the Above")
            self.digits_check.set_active(True)
            self.letters_check.set_active(True)
            box.append(self.digits_check)
            box.append(self.letters_check)
            box.append(self.symbols_check)
            box.append(self.all_above_check)

            generate_btn = Gtk.Button(label="Generate Password")
            generate_btn.connect("clicked", self.generate_password)
            box.append(generate_btn)

            self.result_label = Gtk.Label(label="")
            box.append(self.result_label)

            self.copy_btn = Gtk.Button(label="Copy to Clipboard")
            self.copy_btn.connect("clicked", self.copy_to_clipboard)
            self.copy_btn.set_sensitive(False)
            box.append(self.copy_btn)

        self.window.present()
        
    def view_passwords(self, button):
        key = self.load_key()
        f = Fernet(key)

        try:
            with open("vault.enc", "rb") as file:
                decrypted_data = f.decrypt(file.read())
                passwords = json.loads(decrypted_data)
        except FileNotFoundError:
            self.result_label.set_label("No saved passwords yet.")
            return
        except Exception as e:
            self.result_label.set_label("Error reading vault.")
            print("Vault error:", e)
            return

        # Create a new window
        pw_window = Gtk.Window(title="Saved Passwords")
        pw_window.set_default_size(500, 300)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        listbox = Gtk.ListBox()

        for service, creds in passwords.items():
            row = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            row.append(Gtk.Label(label=f"Service: {service}", xalign=0))
            row.append(Gtk.Label(label=f"Username: {creds['username']}", xalign=0))
            row.append(Gtk.Label(label=f"Password: {creds['password']}", xalign=0))
            separator = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
            row.append(separator)

            listbox.append(row)

        scrolled.set_child(listbox)
        pw_window.set_child(scrolled)
        pw_window.show()


# Logic of the application
    def generate_password(self, button):
        try:
            length = int(self.length_entry.get_text())
            if length <= 0:
                raise ValueError
        except ValueError:
            self.result_label.set_label("Invalid length!")
            self.copy_btn.set_sensitive(False)
            return

        chars = ""
        if self.digits_check.get_active():
            chars += string.digits
        if self.letters_check.get_active():
            chars += string.ascii_letters
        if self.symbols_check.get_active():
            chars += string.punctuation
        if self.all_above_check.get_active():
            chars = string.ascii_letters + string.digits + string.punctuation

        if not chars:
            self.result_label.set_label("No character sets selected!")
            self.copy_btn.set_sensitive(False)
            return

        self.generated_password = ''.join(secrets.choice(chars) for _ in range(length))
        self.result_label.set_label(f"Password: {self.generated_password}")
        self.copy_btn.set_sensitive(True)
        
        service = self.service_entry.get_text()
        username = self.username_entry.get_text()

        if not service or not username:
            self.result_label.set_label("Missing service or username!")
            return

        self.save_password(service, username, self.generated_password)

    
# Saving the password
    def load_key(self):
        try:
            with open("secret.key", "rb") as key_file:
                return key_file.read()
        except FileNotFoundError:
            key = Fernet.generate_key()
            with open("secret.key", "wb") as key_file:
                key_file.write(key)
            return key

    def save_password(self, service, username, password):
        key = self.load_key()
        f = Fernet(key)

        data = {}
        try:
            with open("vault.enc", "rb") as file:
                decrypted_data = f.decrypt(file.read())
                data = json.loads(decrypted_data)
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Error decrypting vault: {e}")
            self.result_label.set_label("Vault decryption failed.")
            return

        data[service] = {"username": username, "password": password}
        encrypted_data = f.encrypt(json.dumps(data).encode())

        with open("vault.enc", "wb") as file:
            file.write(encrypted_data)
        print("[+] Password saved.")
        self.result_label.set_label("Password saved to vault.")


# clipboard functionality
    def copy_to_clipboard(self, button):
        clipboard = Gdk.Display.get_default().get_clipboard()
        text_bytes = GLib.Bytes.new(self.generated_password.encode('utf-8'))
        provider = Gdk.ContentProvider.new_for_bytes("text/plain;charset=utf-8", text_bytes)
        clipboard.set_content(provider)
        self.result_label.set_label("Copied to clipboard!")


app = PasswordGenerator()
app.run()
