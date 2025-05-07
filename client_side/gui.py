import sys
import socket
import threading
from pathlib import Path

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QDialog, QMessageBox,
    QFileDialog, QInputDialog
)

from secure_connection import SecureConnection

# ----------------------------------------------------------------------------
# GUIClient: Handles server communication and tracks clipboard state
# ----------------------------------------------------------------------------

class GUIClient:
    def __init__(self, server_ip="127.0.0.1", server_port=12345):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((server_ip, server_port))
            self.secure_conn = SecureConnection(sock, is_server=False)
        except Exception as e:
            # don’t call QMessageBox here!
            raise ConnectionError(f"Could not reach {server_ip}:{server_port}\n{e}")

        self.token = None
        self.current_path = []
        self.clipboard_name = None
        self.clipboard_action = None

    def create_user(self, username: str, password: str) -> str:
        try:
            self.secure_conn.send_message(f"CREATEUSER {username} {password}")
            return self.secure_conn.receive_message()
        except Exception as e:
            return f"Error during sign-up: {e}"

    def login(self, username: str, password: str):
        try:
            self.secure_conn.send_message(f"LOGIN {username} {password}")
            resp = self.secure_conn.receive_message()
        except Exception as e:
            return False, f"Error during login: {e}"

        if resp.startswith("SUCCESS"):
            parts = resp.split(" ", 2)
            self.token = parts[1] if len(parts) >= 2 else None
            self.current_path = []
            return True, resp
        else:
            return False, resp

    def send(self, cmd: str) -> str:
        if not self.token and not cmd.startswith(("LOGIN", "CREATEUSER")):
            return "ERROR: Not authenticated."
        wrapped = f"TOKEN {self.token} {cmd}" if self.token else cmd
        try:
            self.secure_conn.send_message(wrapped)
            return self.secure_conn.receive_message()
        except Exception as e:
            return f"Error communicating with server: {e}"

    def list(self) -> str:
        return self.send("LIST")

    def cwd(self, folder: str) -> str:
        return self.send(f"CWD {folder}")

    def upload(self, local_path: str) -> str:
        if not Path(local_path).is_file():
            return "ERROR: UPLOAD only supports individual files."
        name = Path(local_path).name
        resp = self.send(f"UPLOAD {name}")
        if not resp.startswith("READY"):
            return resp

        _, port = resp.split()
        host = self.secure_conn.sock.getpeername()[0]
        try:
            self.secure_conn.transfer_file(local_path, host, int(port), "send")
            return f"Uploaded '{name}'"
        except Exception as e:
            return f"Error uploading '{name}': {e}"

    def download(self, name: str, save_path: str) -> str:
        # allow both files and folders (server zips folders for you)
        try:
            resp = self.send(f"DOWNLOAD {name}")
        except Exception as e:
            return f"Error requesting DOWNLOAD: {e}"

        if not resp.startswith("READY"):
            return resp

        _, port = resp.split()
        host = self.secure_conn.sock.getpeername()[0]
        try:
            self.secure_conn.transfer_file(save_path, host, int(port), "receive")
            return f"Downloaded '{name}' → {save_path}"
        except Exception as e:
            return f"Error downloading '{name}': {e}"

    def delete(self, name: str) -> str:
        return self.send(f"DELETE {name}")

    def rename(self, old: str, new: str) -> str:
        return self.send(f"RENAME {old} {new}")

    def copy(self, src: str, dest: str) -> str:
        return self.send(f"COPY {src} {dest}")

    def cut(self, src: str, dest: str) -> str:
        return self.send(f"CUT {src} {dest}")
    def share(self, target_user: str, name: str) -> str:
        try:
            return self.send(f"SHARE {target_user} {name}")
        except Exception as e:
            return f"Error sharing: {e}"


# ----------------------------------------------------------------------------
# Login dialog
# ----------------------------------------------------------------------------
class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Login / Sign Up")
        self.setFixedSize(300, 200)
        layout = QtWidgets.QVBoxLayout(self)

        self.username = QtWidgets.QLineEdit(self)
        self.username.setPlaceholderText("Username")
        self.password = QtWidgets.QLineEdit(self)
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)

        self.login_btn = QtWidgets.QPushButton("Login", self)
        self.signup_btn = QtWidgets.QPushButton("Sign Up", self)
        self.cancel_btn = QtWidgets.QPushButton("Cancel", self)

        layout.addWidget(self.username)
        layout.addWidget(self.password)
        layout.addWidget(self.login_btn)
        layout.addWidget(self.signup_btn)
        layout.addWidget(self.cancel_btn)

        self.login_btn.clicked.connect(self.accept)
        self.cancel_btn.clicked.connect(self.reject)

    def credentials(self):
        return self.username.text(), self.password.text()

# ----------------------------------------------------------------------------
# Main application window
# ----------------------------------------------------------------------------
class MainWindow(QMainWindow):
    log_signal = QtCore.pyqtSignal(str)
    refresh_signal = QtCore.pyqtSignal()

    def __init__(self, client: GUIClient):
        super().__init__()
        self.client = client
        self.setWindowTitle("Secure File Storage")
        self.resize(800, 600)

        toolbar = self.addToolBar("Toolbar")
        toolbar.addAction("Back", self.go_back)
        toolbar.addAction("Upload", self.upload)
        toolbar.addAction("Download", self.download)
        toolbar.addAction("New Folder", self.make_dir)
        toolbar.addAction("Paste", self.paste)
        toolbar.addAction("Refresh", self.populate)
        toolbar.addAction("Logout", self.logout)

        central = QtWidgets.QWidget(self)
        self.setCentralWidget(central)
        layout = QtWidgets.QHBoxLayout(central)

        self.tree = QtWidgets.QTreeView(self)
        self.tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.menu)
        self.tree.doubleClicked.connect(self.on_double_click)

        self.model = QtGui.QStandardItemModel()
        self.model.setHorizontalHeaderLabels(["Name"])
        self.tree.setModel(self.model)

        self.log = QtWidgets.QTextEdit(self)
        self.log.setReadOnly(True)

        layout.addWidget(self.tree, 3)
        layout.addWidget(self.log, 2)

        self.log_signal.connect(self.log.append)
        self.refresh_signal.connect(self.populate)
        self.populate()

    def populate(self):
        self.model.clear()
        self.model.setHorizontalHeaderLabels(["Name"])
        resp = self.client.list()
        if resp.lower().startswith("authentication required"):
            QMessageBox.warning(self, "Error", resp)
            return
        lines = resp.splitlines()[1:] if resp.startswith("Directory listing") else resp.splitlines()
        for name in lines:
            if name.strip():
                self.model.appendRow(QtGui.QStandardItem(name))
        self.tree.expandAll()

    def on_double_click(self, index: QtCore.QModelIndex):
        name = index.data()
        resp = self.client.cwd(name)
        if resp.lower().startswith("changed working directory"):
            rel = resp.split(" to ",1)[1].strip()
            self.client.current_path = [] if rel == "." else rel.split("/")
            self.log_signal.emit(resp)
            self.refresh_signal.emit()

    def go_back(self):
        resp = self.client.cwd("..")
        if resp.lower().startswith("changed working directory"):
            rel = resp.split(" to ",1)[1].strip()
            self.client.current_path = [] if rel == "." else rel.split("/")
        self.log_signal.emit(resp)
        self.refresh_signal.emit()

    def make_dir(self):
        name, ok = QInputDialog.getText(self, "New Folder", "Enter folder name:")
        if ok and name:
            # Run mkdir in a thread to avoid blocking the UI
            def task():
                res = self.client.send(f"MKDIR {name}")
                self.log_signal.emit(res)
                self.refresh_signal.emit()
            threading.Thread(target=task, daemon=True).start()

    def menu(self, pos):
        idx = self.tree.indexAt(pos)
        if not idx.isValid():
            return
        name = idx.data()
        menu = QtWidgets.QMenu(self)
        copy_act   = menu.addAction("Copy")
        cut_act    = menu.addAction("Cut")
        rename_act = menu.addAction("Rename")
        delete_act = menu.addAction("Delete")
        share_act  = menu.addAction("Share")       # ← new!

        action = menu.exec_(self.tree.viewport().mapToGlobal(pos))

        rel = "/".join(self.client.current_path + [name]) if self.client.current_path else name
        if action == copy_act:
            self.client.clipboard_name = rel
            self.client.clipboard_action = 'copy'
            self.log_signal.emit(f"Staged copy: {rel}")
        elif action == cut_act:
            self.client.clipboard_name = rel
            self.client.clipboard_action = 'cut'
            self.log_signal.emit(f"Staged cut: {rel}")
        elif action == rename_act:
            new, ok = QInputDialog.getText(self, "Rename", "New name:", text=name)
            if ok and new:
                res = self.client.rename(name, new)
                self.log_signal.emit(res)
                self.refresh_signal.emit()
        elif action == delete_act:
            res = self.client.delete(name)
            self.log_signal.emit(res)
            self.refresh_signal.emit()
        elif action == share_act:
            user, ok = QInputDialog.getText(
                self,
                "Share File/Folder",
                "Enter username to share with:"
            )
            if ok and user:
                res = self.client.share(user, name)
                self.log_signal.emit(res)

    def paste(self):
        src = self.client.clipboard_name
        act = self.client.clipboard_action
        if not src or act not in ('copy','cut'):
            return
        base = Path(src).name
        dest = f"{base}-copy" if act=='copy' else base
        res1 = self.client.copy(src, dest)
        self.log_signal.emit(res1)
        if act == 'cut':
            res2 = self.client.delete(src)
            self.log_signal.emit(res2)    
    def upload(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Upload")
        if not path:
            return

        # only files allowed
        if not Path(path).is_file():
            QMessageBox.warning(
                self, "Upload Error",
                "Upload only supports individual files."
            )
            return

        threading.Thread(
            target=lambda: self.log_signal.emit(self.client.upload(path)),
            daemon=True
        ).start()

    def download(self):
        idx = self.tree.currentIndex()
        if not idx.isValid():
            return
        name = idx.data()

        # suggest .zip for folders, keep name for files
        default = f"{name}.zip"
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Save File or Folder", default
        )
        if not save_path:
            return

        threading.Thread(
            target=lambda: self.log_signal.emit(
                self.client.download(name, save_path)
            ),
            daemon=True
        ).start()

        self.client.clipboard_name = None
        self.client.clipboard_action = None
        self.refresh_signal.emit()

   
    def logout(self):
        # tell server
        _ = self.client.send("LOGOUT")

        # clear client state
        self.client.token = None
        self.client.current_path = []
        self.client.clipboard_name = None
        self.client.clipboard_action = None

        # hide the main window
        self.hide()

        # show login dialog again
        dlg = LoginDialog()
        dlg.signup_btn.clicked.connect(lambda: self._do_signup(dlg))

        while True:
            if dlg.exec_() != QDialog.Accepted:
                # user hit cancel
                QtWidgets.qApp.quit()
                return

            u, p = dlg.credentials()
            ok, msg = self.client.login(u, p)
            if ok:
                # back in!
                self.show()
                self.populate()
                return
            else:
                QMessageBox.critical(None, "Login Failed", msg)
    def _do_signup(self, dlg: LoginDialog):
        u, p = dlg.credentials()
        if not u or not p:
            QMessageBox.warning(dlg, "Sign Up", "Enter both username and password.")
            return
        res = self.client.create_user(u, p)
        QMessageBox.information(dlg, "Sign Up", res)


# ----------------------------------------------------------------------------
# Application startup
# ----------------------------------------------------------------------------

def do_signup(dlg: LoginDialog, client: GUIClient):
    u, p = dlg.credentials()
    if not u or not p:
        QMessageBox.warning(dlg, "Sign Up", "Enter both username and password.")
        return
    res = client.create_user(u, p)
    QMessageBox.information(dlg, "Sign Up", res)

def main():
    app = QApplication(sys.argv)

    try:
        client = GUIClient()
    except ConnectionError as e:
        QMessageBox.critical(None, "Connection Error", str(e))
        sys.exit(1)

    # initial login loop
    while True:
        dlg = LoginDialog()
        dlg.signup_btn.clicked.connect(lambda d=dlg: do_signup(d, client))

        if dlg.exec_() != QDialog.Accepted:
            sys.exit(0)

        u, p = dlg.credentials()
        ok, msg = client.login(u, p)
        if ok:
            break
        else:
            QMessageBox.critical(None, "Login Failed", msg)

    window = MainWindow(client)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()