# utils/resources.py
import sys
import os
import logging
from PyQt5.QtGui import QFontDatabase
from PyQt5.QtWidgets import QApplication

def get_resource_path(relative_path):
    """Hämtar den absoluta sökvägen till resursen, fungerar för utveckling och PyInstaller."""
    base_path = getattr(sys, '_MEIPASS', os.path.abspath("."))
    return os.path.join(base_path, relative_path)

def load_custom_fonts():
    # Ladda custom typsnitt från assets
    font_files = [
        "MesloLGMNerdFont-Regular.ttf",
        "MesloLGMNerdFont-Bold.ttf",
        "MesloLGMNerdFont-Italic.ttf",
        "MesloLGMNerdFont-BoldItalic.ttf"
    ]
    for font_file in font_files:
        font_path = get_resource_path(os.path.join("assets", font_file))
        font_id = QFontDatabase.addApplicationFont(font_path)
        if font_id == -1:
            logging.warning(f"Kunde inte ladda typsnittet: {font_file}")
        else:
            font_family = QFontDatabase.applicationFontFamilies(font_id)[0]
            logging.info(f"Typsnitt laddat: {font_family}")

def apply_style(target):
    """
    Applicera stylesheet och ladda typsnitt.
    Om target är en QApplication, applicera globalt.
    Annars applicera på specifikt widget/dialog.
    """
    load_custom_fonts()
    style_sheet_path = get_resource_path("styles.qss")
    if os.path.exists(style_sheet_path):
        with open(style_sheet_path, "r") as f:
            style_sheet = f.read()
        target.setStyleSheet(style_sheet)
    else:
        logging.warning("Stylesheet 'styles.qss' hittades inte.")
