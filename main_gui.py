"""
Audit Sentinel – Interface Gráfica Profissional, Análise Multidomínio e Exportação Completa
"""

import os, sys
data_path = os.path.join(os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__), "public_suffix_list.dat")
os.environ['PUBLIC_SUFFIX_LIST_PATH'] = data_path

import csv
import json
import datetime
import re
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QTextEdit, QStackedWidget, QFileDialog, QMessageBox,
    QProgressBar, QDialog
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QIcon, QTextCursor, QMovie, QAction

import auditor_core
import config

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def ere_html(block, search_text=""):
    if block.get('title', '').startswith('======='):
        return f"<pre style='color:#00ffff; font-weight:bold; font-size:14px; text-align:center; margin:15px 0;'>{block['title']}</pre><br>"
    def highlight(text):
        if not search_text:
            return text
        return re.sub(f"({re.escape(search_text)})", r"<span style='background-color:yellow; color:black;'>\1</span>", text, flags=re.IGNORECASE)
    title = f"<div style='color:#00ffff; font-weight:bold; font-size:16px; margin-top:12px;'>{highlight(block.get('title', ''))}</div>"
    expl = f"<div style='color:#ccc; font-style:italic; margin-bottom:5px;'>{highlight(block.get('explanation', ''))}</div>"
    results_html = ""
    color_map = {'good': '#00FF00', 'bad': '#FF0000', 'alert': '#FFFF00', 'info': '#FFFFFF'}
    for r in block.get('results', []):
        text = r.get('text', '').replace('<', '&lt;').replace('>', '&gt;')
        style = f"color:{color_map.get(r.get('status'),'#FFFFFF')}; margin-left:14px;"
        if r.get('underline'):
            style += "text-decoration: underline;"
        results_html += f"<div style='{style}'>{highlight(text)}</div>"
    verdict = f"<div style='font-weight:bold; color:#fff; margin-top:3px;'>{highlight(block.get('verdict', ''))}</div>"
    if block.get('suggestion'):
        verdict += f"<div style='color:#00BFFF; margin-top:2px;'><b>Sugestão:</b> {block['suggestion']}</div>"
    return title + expl + results_html + verdict

class AnalysisThread(QThread):
    result_signal = Signal(dict)
    progress_signal = Signal(int, str)
    anomaly_signal = Signal(str)
    done_signal = Signal()

    def __init__(self, func, domain_list):
        super().__init__()
        self.func = func
        self.domain_list = domain_list

    def run(self):
        try:
            analysis_blocks = list(self.func(self.domain_list))
            total_blocks = len(analysis_blocks)
            for i, block in enumerate(analysis_blocks):
                if self.isInterruptionRequested():
                    self.anomaly_signal.emit("Análise interrompida pelo usuário.")
                    return
                self.result_signal.emit(block)
                progress_percent = int(((i + 1) / total_blocks) * 100)
                self.progress_signal.emit(progress_percent, f"Analisando: {block.get('title', '...')}")
                self.msleep(30)
        except Exception as e:
            self.anomaly_signal.emit(f"ERRO CRÍTICO NA THREAD: {e}")
        finally:
            self.progress_signal.emit(100, "Análise Concluída!")
            self.done_signal.emit()

class AnalysisScreen(QWidget):
    def __init__(self, screen_title, analysis_func, stack):
        super().__init__()
        self.screen_title = screen_title
        self.analysis_func = analysis_func
        self.stack = stack
        self.thread = None
        self.is_running = False
        self.last_results_for_export = []
        self.full_report_html = ""

        main_layout = QHBoxLayout(self)
        left_pane = QWidget()
        right_pane = QWidget()
        main_layout.addWidget(left_pane, 1)
        main_layout.addWidget(right_pane, 2)

        left_layout = QVBoxLayout(left_pane)
        self.anim_label = QLabel()
        gif_path = resource_path("matrix.gif")
        if os.path.exists(gif_path):
            movie = QMovie(gif_path)
            self.anim_label.setMovie(movie)
            movie.start()
        self.dom_input = QTextEdit()
        self.dom_input.setPlaceholderText("Digite ou cole domínios e/ou e-mails separados por vírgula, espaço ou quebra de linha.")
        self.dom_input.setToolTip("Você pode inserir vários domínios ou e-mails, separados por vírgula, espaço ou linha.")
        self.load_txt_button = QPushButton("Carregar de TXT")
        input_layout = QHBoxLayout()
        input_layout.addWidget(self.load_txt_button)
        left_layout.addWidget(QLabel(f"<b>Domínio(s) / e-mails para {screen_title}:</b>"))
        left_layout.addWidget(self.dom_input)
        left_layout.addLayout(input_layout)
        self.anom_box = QTextEdit(readOnly=True)
        self.anom_box.setObjectName("Anomalias")
        self.go_button = QPushButton("EXECUTAR ANÁLISE")
        self.stop_clear_button = QPushButton("LIMPAR")
        self.back_button = QPushButton("← MENU")
        left_layout.addWidget(self.go_button)
        left_layout.addWidget(self.stop_clear_button)
        left_layout.addWidget(self.back_button)
        left_layout.addWidget(self.anim_label, alignment=Qt.AlignCenter)
        left_layout.addStretch()
        left_layout.addWidget(QLabel("<b>Anomalias Detectadas:</b>"))
        left_layout.addWidget(self.anom_box)

        right_layout = QVBoxLayout(right_pane)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Buscar no relatório...")
        self.res_box = QTextEdit(readOnly=True)
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.status_label = QLabel("Pronto para iniciar a análise.")
        self.status_label.setAlignment(Qt.AlignCenter)
        bottom_buttons_layout = QHBoxLayout()
        self.copy_button = QPushButton("Copiar Relatório")
        self.export_csv_button = QPushButton("Exportar CSV")
        self.export_json_button = QPushButton("Exportar JSON")
        self.export_csv_button.clicked.connect(self.export_csv)
        self.export_json_button.clicked.connect(self.export_json)
        self.export_csv_button.setEnabled(False)
        self.export_json_button.setEnabled(False)
        bottom_buttons_layout.addWidget(self.copy_button)
        bottom_buttons_layout.addWidget(self.export_csv_button)
        bottom_buttons_layout.addWidget(self.export_json_button)
        right_layout.addWidget(QLabel("<b>Resultados Detalhados:</b>"))
        right_layout.addWidget(self.search_input)
        right_layout.addWidget(self.res_box)
        right_layout.addWidget(self.progress_bar)
        right_layout.addWidget(self.status_label)
        right_layout.addLayout(bottom_buttons_layout)

        self.go_button.clicked.connect(self.start_analysis)
        self.stop_clear_button.clicked.connect(self.stop_or_clear)
        self.back_button.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.copy_button.clicked.connect(self.copy_report)
        self.load_txt_button.clicked.connect(self.load_from_txt)
        self.search_input.textChanged.connect(self.search_in_report)

    def start_analysis(self):
        raw_text = self.dom_input.toPlainText()
        # Split por vírgula, espaço, linha
        items = [d.strip() for d in re.split(r"[\s,;]+", raw_text) if d.strip()]
        if not items or self.is_running:
            return
        self.res_box.clear()
        self.anom_box.clear()
        self.full_report_html = ""
        self.last_results_for_export = []
        self.export_csv_button.setEnabled(False)
        self.export_json_button.setEnabled(False)
        self.go_button.setEnabled(False)
        self.stop_clear_button.setText("PARAR")
        self.is_running = True
        self.progress_bar.setValue(0)
        self.status_label.setText("Iniciando análise...")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        self.thread = AnalysisThread(self.analysis_func, items)
        self.thread.result_signal.connect(self.append_result)
        self.thread.anomaly_signal.connect(self.append_anomaly)
        self.thread.progress_signal.connect(self.update_progress)
        self.thread.done_signal.connect(self.analysis_done)
        self.thread.start()

    def stop_or_clear(self):
        if self.is_running:
            if self.thread and self.thread.isRunning():
                self.thread.requestInterruption()
        else:
            self.res_box.clear()
            self.anom_box.clear()
            self.dom_input.clear()
            self.export_csv_button.setEnabled(False)
            self.export_json_button.setEnabled(False)
            self.progress_bar.setValue(0)
            self.status_label.setText("Pronto para iniciar a análise.")

    def append_result(self, block):
        if 'export_data' in block:
            self.last_results_for_export = block['export_data']
            return
        html_block = ere_html(block) + "<br>"
        self.full_report_html += html_block
        self.res_box.moveCursor(QTextCursor.End)
        self.res_box.insertHtml(html_block)
        self.res_box.moveCursor(QTextCursor.End)
        for r in block.get('results', []):
            if r.get('status') in ('bad', 'alert'):
                self.append_anomaly(r.get('text', 'Anomalia não especificada'))

    def append_anomaly(self, text):
        self.anom_box.append(text.replace('<', '&lt;').replace('>', '&gt;'))

    def update_progress(self, value, message):
        self.progress_bar.setValue(value)
        self.status_label.setText(message)

    def analysis_done(self):
        self.is_running = False
        self.go_button.setEnabled(True)
        self.stop_clear_button.setText("LIMPAR")
        QApplication.restoreOverrideCursor()
        if self.last_results_for_export:
            self.export_csv_button.setEnabled(True)
            self.export_json_button.setEnabled(True)
        if self.thread:
            self.thread.quit()
            self.thread.wait()
        self.thread = None

    def copy_report(self):
        QApplication.clipboard().setText(self.res_box.toPlainText())
        self.copy_button.setText("COPIADO!")
        QTimer.singleShot(2000, lambda: self.copy_button.setText("Copiar Relatório"))

    def export_csv(self):
        if not self.last_results_for_export:
            QMessageBox.warning(self, "Exportar", "Nenhum dado disponível para exportação.")
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório CSV", f"relatorio_{datetime.date.today()}.csv", "CSV Files (*.csv)")
        if not filename: return
        try:
            # Gera header dinâmico unindo todas as chaves de todos os domínios
            header = set()
            for d in self.last_results_for_export:
                header.update(d.keys())
            header = list(header)
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=header)
                writer.writeheader()
                for row in self.last_results_for_export:
                    writer.writerow(row)
            QMessageBox.information(self, "Sucesso", f"Relatório salvo com sucesso em:\n{filename}")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Não foi possível salvar o arquivo:\n{e}")

    def export_json(self):
        if not self.last_results_for_export:
            QMessageBox.warning(self, "Exportar", "Nenhum dado disponível para exportação.")
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Salvar Relatório JSON", f"relatorio_{datetime.date.today()}.json", "JSON Files (*.json)")
        if not filename: return
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.last_results_for_export, f, indent=4, ensure_ascii=False)
            QMessageBox.information(self, "Sucesso", f"Relatório salvo com sucesso em:\n{filename}")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Não foi possível salvar o arquivo:\n{e}")

    def load_from_txt(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Carregar Domínios de Arquivo", "", "Text Files (*.txt)")
        if not filename: return
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                domains = [line.strip() for line in f if line.strip()]
            self.dom_input.setText('\n'.join(domains))
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Não foi possível ler o arquivo:\n{e}")

    def search_in_report(self, text):
        if not text:
            self.res_box.setHtml(self.full_report_html)
        else:
            cursor = self.res_box.document().find(text, 0)
            if cursor:
                self.res_box.setTextCursor(cursor)

class AboutScreen(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sobre o Audit Sentinel")
        self.setMinimumWidth(400)
        layout = QVBoxLayout(self)
        title = QLabel("Audit Sentinel v2.0")
        title.setStyleSheet("font-size: 20px; font-weight: bold;")
        info = QLabel(
            "Ferramenta de Análise de Domínio, E-mail e OSINT.\n\n"
            "Desenvolvido para fornecer diagnósticos de segurança e configuração de forma pratica e acessível.\n\n"
            "(c) 2025 - Lucas Zafalon / Meu Marketing Contábil"
        )
        close_button = QPushButton("Fechar")
        close_button.clicked.connect(self.accept)
        layout.addWidget(title, alignment=Qt.AlignCenter)
        layout.addWidget(info, alignment=Qt.AlignCenter)
        layout.addWidget(close_button)

class MenuScreen(QWidget):
    def __init__(self, stack):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(50, 50, 50, 50)
        layout.addStretch(2)
        title_label = QLabel("<div style='font-size:32px; color:#00FF00; text-align:center;'>AUDIT SENTINEL</div>")
        layout.addWidget(title_label, alignment=Qt.AlignCenter)
        buttons_layout = QVBoxLayout()
        buttons_layout.setSpacing(15)
        buttons_config = [
            ("Análise Completa (OSINT)", 1, "Executa todas as checagens: DNS, WHOIS, SSL, portas, subdomínios, etc."),
            ("Diagnóstico de Domínio", 2, "Verifica a configuração essencial do domínio: DNS, WHOIS e SSL."),
            ("Auditoria de E-mail", 3, "Analisa a segurança de e-mails: MX, SPF, DKIM, DMARC, harvesting, OSINT."),
            ("Análise de WHOIS em Massa", 4, "Consulta informações de registro para múltiplos domínios de uma só vez.")
        ]
        for text, index, tooltip in buttons_config:
            btn = QPushButton(text)
            btn.setToolTip(tooltip)
            btn.setMinimumHeight(50)
            btn.setMinimumWidth(350)
            btn.clicked.connect(lambda checked=False, i=index: stack.setCurrentIndex(i))
            buttons_layout.addWidget(btn, alignment=Qt.AlignCenter)
        layout.addLayout(buttons_layout)
        self.menu_anim_label = QLabel()
        self.menu_anim_label.setAlignment(Qt.AlignCenter)
        gif_path = resource_path("matrix.gif")
        if os.path.exists(gif_path):
            movie = QMovie(gif_path)
            self.menu_anim_label.setMovie(movie)
            movie.start()
        layout.addWidget(self.menu_anim_label, alignment=Qt.AlignCenter)
        layout.addStretch(3)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Audit Sentinel – Premium GUI")
        try:
            self.setWindowIcon(QIcon(resource_path("app_icon.ico")))
        except:
            print("WARNING: app_icon.ico not found.")
        self.setMinimumSize(1200, 800)
        self._create_menus()
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack)
        self.menu = MenuScreen(self.stack)
        self.osint_screen = AnalysisScreen("Análise Completa (OSINT)", auditor_core.analyze_osint, self.stack)
        self.domain_screen = AnalysisScreen("Diagnóstico de Domínio", auditor_core.analyze_domain, self.stack)
        self.email_screen = AnalysisScreen("Auditoria de E-mail", auditor_core.analyze_email, self.stack)
        self.whois_screen = AnalysisScreen("Análise de WHOIS em Massa", auditor_core.analyze_whois_bulk, self.stack)
        self.stack.addWidget(self.menu)
        self.stack.addWidget(self.osint_screen)
        self.stack.addWidget(self.domain_screen)
        self.stack.addWidget(self.email_screen)
        self.stack.addWidget(self.whois_screen)
        try:
            with open(resource_path("style.qss"), "r", encoding="utf-8") as f:
                self.setStyleSheet(f.read())
        except Exception as e:
            print(f"ERROR: Could not load stylesheet (style.qss): {e}")

    def _create_menus(self):
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("&Arquivo")
        exit_action = QAction("Sair", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        help_menu = menu_bar.addMenu("&Ajuda")
        about_action = QAction("Sobre", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

    def show_about_dialog(self):
        about_dialog = AboutScreen(self)
        about_dialog.exec()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
