"""
Module: sfs_main.py
Description: Single entry point for the SFS, with a single CLI that handles both admin tasks
             (addgroup, adduser) and user tasks (login, logout, cd, ls, touch, echo, etc.).
             Updated so that each new user's home directory has 'group' permission, allowing
             same-group users to see it (but see file names as encrypted).
"""

import os
import logging
from sfs.authentication import AuthManager
from sfs.encryption import generate_key
from sfs.models import User, Directory
from sfs.filesystem import FileSystem
from sfs.disk_storage import SFS_DATA_FOLDER, write_directory_to_disk, scan_directory_recursive
from sfs.permission import change_permission

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    # Ensure the on-disk folder exists
    if not os.path.exists(SFS_DATA_FOLDER):
        os.makedirs(SFS_DATA_FOLDER)

    # Initialize authentication manager
    auth_manager = AuthManager()
    # Generate a single encryption key for everything
    key = generate_key()

    # Create an "admin" user for controlling groups/users.
    try:
        admin_user = auth_manager.create_user(
            "admin", "adminpass", is_admin=True)
    except ValueError:
        admin_user = auth_manager.get_user("admin")

    # Create or load the "home" root directory (plaintext "home" folder on disk)
    root_dir = Directory("home", owner=admin_user, permissions="all")
    write_directory_to_disk(root_dir, key)

    # Build the FileSystem object
    fs = FileSystem(root_dir, key)

    # Re-scan from disk in case there is an existing structure
    user_map = {u.username: u for u in auth_manager.users.values()}
    scan_directory_recursive(root_dir, key, user_map)

    current_user = None  # No one is logged in at start

    print("Welcome to the Secure File System. Type 'help' for commands, 'exit' to quit.")

    while True:
        cmd = input("SFS> ").strip()
        if cmd == "exit":
            break

        if cmd == "help":
            print("Commands:")
            print("  addgroup <groupname>              (admin only)")
            print("  adduser <username> <password> <groupname>  (admin only)")
            print("  login <username> <password>")
            print("  logout")
            print("  pwd")
            print("  ls")
            print("  mkdir <dirname>")
            print("  rmdir <dirname>")
            print("  touch <filename>")
            print("  rm <filename>")
            print("  cd <dirname>")
            print("  cat <filename>")
            print("  echo <filename> <text>")
            print("  mv <old_name> <new_name>")
            print("  chmod <file_or_dir> <user|group|all>")
            print("  exit")
            continue

        parts = cmd.split()
        if not parts:
            continue

        if parts[0] == "addgroup":
            # e.g. addgroup team1
            if not current_user or not current_user.is_admin:
                print("Only admin can create groups.")
                continue
            if len(parts) < 2:
                print("Usage: addgroup <name>")
                continue
            grpname = parts[1]
            try:
                auth_manager.create_group(grpname)
                print(f"Group '{grpname}' created.")
            except ValueError as e:
                print(str(e))

        elif parts[0] == "adduser":
            # e.g. adduser User1 pass1 team1
            if not current_user or not current_user.is_admin:
                print("Only admin can add users.")
                continue
            if len(parts) < 4:
                print("Usage: adduser <username> <password> <groupname>")
                continue
            uname, pwd, grp = parts[1], parts[2], parts[3]
            try:
                newu = auth_manager.create_user(uname, pwd, grp)
                print(f"User '{uname}' created in group '{grp}'.")
                # Make them a home directory in /home with 'group' permission
                user_home = Directory(uname, owner=newu, permissions='group')
                root_dir.add_subdirectory(user_home)
                write_directory_to_disk(user_home, key)
                print(
                    f"Home directory '/home/{uname}' created with 'group' permission.")
            except ValueError as e:
                print(str(e))

        elif parts[0] == "login":
            # e.g. login User1 pass1
            if len(parts) < 3:
                print("Usage: login <username> <password>")
                continue
            uname, pwd = parts[1], parts[2]
            if auth_manager.login(uname, pwd):
                current_user = auth_manager.get_user(uname)
                print(f"You are now logged in as {current_user.username}.")
                # Move the FileSystem to that user's home if it exists
                # then do an integrity check
                found_home = None
                for sd in root_dir.subdirectories:
                    if sd.dir_name == current_user.username:
                        found_home = sd
                        break
                if found_home:
                    fs.current_directory = found_home
                    fs.check_user_home_integrity(current_user, found_home)
                else:
                    # If they don't have a home, default to /home
                    fs.current_directory = root_dir
            else:
                print("Login failed. Invalid username/password.")

        elif parts[0] == "logout":
            if current_user:
                print(f"User '{current_user.username}' logged out.")
            current_user = None
            fs.current_directory = root_dir

        elif parts[0] == "pwd":
            if not current_user:
                print("No user logged in.")
                continue
            print(fs.pwd())

        elif parts[0] == "ls":
            if not current_user:
                print("No user logged in.")
                continue
            items = fs.ls(current_user)
            if items:
                print(" ".join(items))
            else:
                print("(empty or no permission)")

        elif parts[0] == "mkdir":
            if len(parts) < 2:
                print("Usage: mkdir <dirname>")
                continue
            if not current_user:
                print("No user logged in.")
                continue
            dirname = parts[1]
            if fs.mkdir(current_user, dirname):
                print(f"Directory '{dirname}' created.")
            else:
                print("mkdir failed (no permission or error).")

        elif parts[0] == "rmdir":
            if len(parts) < 2:
                print("Usage: rmdir <dirname>")
                continue
            if not current_user:
                print("No user logged in.")
                continue
            dirname = parts[1]
            if fs.rmdir(current_user, dirname):
                print(f"Directory '{dirname}' removed.")
            else:
                print("rmdir failed (no permission, not empty, or not found).")

        elif parts[0] == "touch":
            if len(parts) < 2:
                print("Usage: touch <filename>")
                continue
            if not current_user:
                print("No user logged in.")
                continue
            fname = parts[1]
            if fs.touch(current_user, fname):
                print(f"File '{fname}' created.")
            else:
                print("touch failed (no permission).")

        elif parts[0] == "rm":
            if len(parts) < 2:
                print("Usage: rm <filename>")
                continue
            if not current_user:
                print("No user logged in.")
                continue
            fname = parts[1]
            if fs.rm(current_user, fname):
                print(f"File '{fname}' removed.")
            else:
                print("rm failed (no permission or file not found).")

        elif parts[0] == "cd":
            if len(parts) < 2:
                print("Usage: cd <dirname>")
                continue
            if not current_user:
                print("No user logged in.")
                continue
            dirname = parts[1]
            if fs.cd(current_user, dirname):
                print(f"Changed directory to '{dirname}'.")
            else:
                print("cd failed (no permission or not found).")

        elif parts[0] == "cat":
            if len(parts) < 2:
                print("Usage: cat <filename>")
                continue
            if not current_user:
                print("No user logged in.")
                continue
            fname = parts[1]
            content = fs.cat(current_user, fname)
            print(content)

        elif parts[0] == "echo":
            if len(parts) < 3:
                print("Usage: echo <filename> <text>")
                continue
            if not current_user:
                print("No user logged in.")
                continue
            fname = parts[1]
            text = " ".join(parts[2:])
            if fs.echo(current_user, fname, text):
                print("Wrote text successfully.")
            else:
                print("echo failed (no permission or file not found).")

        elif parts[0] == "mv":
            if len(parts) < 3:
                print("Usage: mv <old_name> <new_name>")
                continue
            if not current_user:
                print("No user logged in.")
                continue
            oldn, newn = parts[1], parts[2]
            if fs.mv(current_user, oldn, newn):
                print(f"Renamed '{oldn}' to '{newn}'.")
            else:
                print("mv failed (no permission or not found).")

        elif parts[0] == "chmod":
            if len(parts) < 3:
                print("Usage: chmod <file_or_dir> <user|group|all>")
                continue
            if not current_user:
                print("No user logged in.")
                continue
            target_name = parts[1]
            new_perm = parts[2]
            # Find the file or directory in the current directory
            found_target = None
            for f in fs.current_directory.files:
                if f.file_name == target_name:
                    found_target = f
                    break
            if not found_target:
                for d in fs.current_directory.subdirectories:
                    if d.dir_name == target_name:
                        found_target = d
                        break
            if not found_target:
                print("File or directory not found.")
            else:
                if change_permission(found_target, new_perm, current_user):
                    print(f"Permission changed to '{new_perm}'.")
                else:
                    print("chmod failed (not owner or invalid perm).")

        else:
            print("Unknown command. Type 'help' for usage.")

    print("Exiting SFS. Goodbye.")


if __name__ == "__main__":
    main()
