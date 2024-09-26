# gui/widgets.py
from PyQt5.QtWidgets import QListWidget, QMessageBox
from PyQt5.QtCore import Qt
import os

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

class DropListWidget(QListWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.parent = parent
        self.setSelectionMode(QListWidget.ExtendedSelection)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            for url in event.mimeData().urls():
                filepath = url.toLocalFile()
                if os.path.isfile(filepath):
                    if os.path.getsize(filepath) > MAX_FILE_SIZE:
                        QMessageBox.warning(self, "Fel", f"Filen {filepath} överstiger maximal tillåten storlek.")
                    else:
                        if filepath not in self.parent.file_list:
                            self.parent.file_list.append(filepath)
                            self.addItem(filepath)
        else:
            event.ignore()
