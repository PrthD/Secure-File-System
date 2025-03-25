import os
import logging
from sfs.authentication import AuthManager
from sfs.encryption import generate_key
from sfs.models import User, Directory
from sfs.filesystem import FileSystem
from sfs.disk_storage import SFS_DATA_FOLDER, write_directory_to_disk, scan_directory_recursive, load_directory_from_disk
from sfs.permission import change_permission

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ADDED: Persist the key to a file so that the same key is used every session.
KEYFILE_PATH = os.path.join(SFS_DATA_FOLDER, "sfs_key.bin")


def load_or_create_key() -> bytes:
    """
    Loads the encryption key from disk if present; otherwise generates a new key once,
    saves it, and reuses it on subsequent runs.
    """
    if os.path.exists(KEYFILE_PATH):
        with open(KEYFILE_PATH, "rb") as f:
            return f.read()
    else:
        new_key = generate_key()
        with open(KEYFILE_PATH, "wb") as f:
            f.write(new_key)
        return new_key


def main():
    # Ensure the on-disk folder exists
    if not os.path.exists(SFS_DATA_FOLDER):
        os.makedirs(SFS_DATA_FOLDER)

    auth_manager = AuthManager()

    # CHANGED: Instead of generating a new key each time, load/create once.
    key = load_or_create_key()

    try:
        admin_user = auth_manager.create_user(
            "admin", "adminpass", is_admin=True
        )
    except ValueError:
        admin_user = auth_manager.get_user("admin")

    existing_home = load_directory_from_disk("home", key)
    if existing_home is not None:
        # We have an existing home directory on disk - reuse it
        root_dir = existing_home
        # Optionally, ensure it has the correct owner or perms:
        root_dir.owner = admin_user
        root_dir.permissions = "all"
    else:
        # If there's no "home" on disk, create it fresh
        root_dir = Directory("home", owner=admin_user, permissions="all")
        write_directory_to_disk(root_dir, key)

    fs = FileSystem(root_dir, key)

    # For the initial load, we can do a minimal scan if you wish
    user_map = {u.username: u for u in auth_manager.users.values()}
    subdirs, files = scan_directory_recursive(root_dir, key, user_map)
    # In a bigger system, unify them with root_dir. For now, let's skip.

    current_user = None

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
                user_home = Directory(uname, owner=newu, permissions='group')
                root_dir.add_subdirectory(user_home)
                write_directory_to_disk(user_home, key)
                print(
                    f"Home directory '/home/{uname}' created with 'group' permission."
                )
            except ValueError as e:
                print(str(e))

        elif parts[0] == "login":
            if len(parts) < 3:
                print("Usage: login <username> <password>")
                continue
            uname, pwd = parts[1], parts[2]
            if auth_manager.login(uname, pwd):
                current_user = auth_manager.get_user(uname)
                print(f"You are now logged in as {current_user.username}.")
                # Move the FileSystem to that user's home if it exists, then do an integrity check
                found_home = None
                for sd in root_dir.subdirectories:
                    if sd.dir_name == current_user.username:
                        found_home = sd
                        break
                if found_home:
                    fs.current_directory = found_home
                    fs.check_user_home_integrity(current_user, found_home)
                else:
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
