import sys
from PyQt5.QtWidgets import QApplication
from vpn_gui import VPNMainWindow

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = VPNMainWindow()
    window.show()
    sys.exit(app.exec_())
