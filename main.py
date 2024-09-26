# main.py
import sys
from PyQt5.QtWidgets import QApplication
from gui.main_window import MainWindow
from utils.resources import apply_style

def main():
    app = QApplication(sys.argv)
    apply_style(app)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
