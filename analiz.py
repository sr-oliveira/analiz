import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from fpdf import FPDF
import requests
from bs4 import BeautifulSoup
from scapy.all import sniff, IP
import jsbeautifier
import re
import os
import sys
import ctypes
import hashlib

class WebAnalyzerApp:
    def __init__(self, root):
        self.root = root
        root.title("Analiz Web")
        self.padroes_incomuns = ['SQL.*error', 'acesso\s+não\s+autorizado', 'padrão\s+incomum']
        self.tentativas_exploracao = ['DROP\s+TABLE', 'UNION\s+SELECT', 'tentativa\s+de\s+exploração']
        self.create_widgets()

    def create_widgets(self):
        # Label e Entry para o URL alvo
        self.label_url = ttk.Label(self.root, text="URL Alvo:")
        self.label_url.grid(column=0, row=0, padx=10, pady=5, sticky=tk.W)

        self.entry_url = ttk.Entry(self.root, width=50)
        self.entry_url.insert(0, 'https://exemplo.com/')
        self.entry_url.grid(column=1, row=0, padx=10, pady=5, sticky=tk.W)

        # Botão para iniciar a análise
        self.btn_analisar = ttk.Button(self.root, text="Analisar", command=self.analisar)
        self.btn_analisar.grid(column=2, row=0, padx=10, pady=5)

        # Botão para descompilar JavaScript
        self.btn_descompilar_js = ttk.Button(self.root, text="Descompilar JS", command=self.descompilar_js)
        self.btn_descompilar_js.grid(column=3, row=0, padx=10, pady=5)

        # Botão para verificar segurança
        self.btn_verificar_seguranca = ttk.Button(self.root, text="Verificar Segurança", command=self.verificar_seguranca)
        self.btn_verificar_seguranca.grid(column=6, row=0, padx=10, pady=5)

        # Área de exibição de resultados
        self.results_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=20)
        self.results_text.grid(column=0, row=1, columnspan=7, padx=10, pady=5)

        # Botão para exportar resultados como CSV
        self.btn_exportar_csv = ttk.Button(self.root, text="Exportar CSV", command=self.exportar_csv)
        self.btn_exportar_csv.grid(column=4, row=0, padx=10, pady=5)

        # Botão para exportar resultados como PDF
        self.btn_exportar_pdf = ttk.Button(self.root, text="Exportar PDF", command=self.exportar_pdf)
        self.btn_exportar_pdf.grid(column=5, row=0, padx=10, pady=5)

    def analisar(self):
        # Limpar a área de exibição de resultados
        self.results_text.delete(1.0, tk.END)

        # Obter o URL do Entry
        url_alvo = self.entry_url.get()

        # Obtém o código-fonte da página
        codigo_fonte = self.obter_codigo_fonte(url_alvo)
        if codigo_fonte:
            # Captura e processa alguns pacotes
            self.capturar_e_processar_pacotes()

            # Descompila código JavaScript (exemplo: primeiro script encontrado)
            soup = BeautifulSoup(codigo_fonte, 'html.parser')
            script = soup.find('script')
            if script:
                codigo_js = script.text
                codigo_descompilado = self.descompilar_javascript(codigo_js)
                self.exibir_resultado("Código JavaScript Descompilado:\n" + codigo_descompilado)

            # Reconhecimento de tecnologia
            self.reconhecimento_tecnologia(url_alvo)

    def descompilar_js(self):
        # Obter o URL do Entry
        url_alvo = self.entry_url.get()

        # Obtém o código-fonte da página
        codigo_fonte = self.obter_codigo_fonte(url_alvo)
        if codigo_fonte:
            # Descompila código JavaScript (exemplo: primeiro script encontrado)
            soup = BeautifulSoup(codigo_fonte, 'html.parser')
            script = soup.find('script')
            if script:
                codigo_js = script.text
                codigo_descompilado = self.descompilar_javascript(codigo_js)

                # Exibir o resultado em uma nova janela
                self.exibir_resultado_em_janela("Código JavaScript Descompilado", codigo_descompilado)

    def obter_codigo_fonte(self, url):
        try:
            self.exibir_resultado(f"Iniciando obter_codigo_fonte para URL: {url}")
            resposta = requests.get(url, timeout=10)
            resposta.raise_for_status()
            self.exibir_resultado("obter_codigo_fonte concluído.")
            return resposta.text
        except requests.exceptions.RequestException as err:
            self.exibir_resultado(f"Erro na requisição HTTP: {err}")
            return None

    def capturar_e_processar_pacotes(self, qtd_pacotes=5):
        def processar_pacote(pacote):
            if IP in pacote:
                self.exibir_resultado(f"IP Origem: {pacote[IP].src}, IP Destino: {pacote[IP].dst}")

        self.exibir_resultado(f"Iniciando capturar_e_processar_pacotes (capturando {qtd_pacotes} pacotes)")
        sniff(prn=processar_pacote, count=qtd_pacotes)
        self.exibir_resultado("capturar_e_processar_pacotes concluído.")

    def descompilar_javascript(self, codigo_minificado):
        try:
            self.exibir_resultado("Iniciando descompilar_javascript")
            codigo_descompilado = jsbeautifier.beautify(codigo_minificado)
            self.exibir_resultado("descompilar_javascript concluído.")
            return codigo_descompilado
        except Exception as e:
            self.exibir_resultado(f"Erro na descompilação do JavaScript: {e}")
            return None

    def reconhecimento_tecnologia(self, url):
        try:
            self.exibir_resultado(f"Iniciando reconhecimento_tecnologia para URL: {url}")
            resposta = requests.get(url, timeout=10)
            resposta.raise_for_status()

            cabecalhos = resposta.headers
            self.exibir_resultado("Cabeçalhos HTTP:")
            for chave, valor in cabecalhos.items():
                self.exibir_resultado(f"{chave}: {valor}")

            soup = BeautifulSoup(resposta.text, 'html.parser')
            tecnologias = self.identificar_tecnologias(soup, codigo_fonte=resposta.text, cabecalhos=cabecalhos)

            self.exibir_resultado("\nTecnologias Identificadas:")
            if tecnologias:
                for tecnologia in tecnologias:
                    self.exibir_resultado(tecnologia)
            else:
                self.exibir_resultado("Nenhuma tecnologia identificada.")
        except requests.exceptions.RequestException as err:
            self.exibir_resultado(f"Erro na requisição HTTP: {err}")
        finally:
            self.exibir_resultado("reconhecimento_tecnologia concluído.")

    def identificar_tecnologias(self, soup, codigo_fonte, cabecalhos):
        tecnologias = []

        # Verificar tecnologias no HTML
        if soup.find(string=re.compile(r'Python', re.I)):
            tecnologias.append("Python")

        if soup.find('script', {'src': re.compile(r'jquery', re.I)}):
            tecnologias.append("jQuery")

        # Verificar tecnologias nos scripts
        if re.search(r'react', codigo_fonte, re.I):
            tecnologias.append("React")

        if re.search(r'angular', codigo_fonte, re.I):
            tecnologias.append("Angular")

        if re.search(r'express', codigo_fonte, re.I):
            tecnologias.append("Express.js")

        # Verificar tecnologias nos cabeçalhos HTTP
        server_header = cabecalhos.get('Server', '').lower()
        if 'php' in server_header:
            tecnologias.append("PHP")

        x_powered_by_header = cabecalhos.get('X-Powered-By', '').lower()
        if 'asp.net' in x_powered_by_header:
            tecnologias.append("ASP.NET")

        return tecnologias

    def exibir_resultado(self, mensagem):
        self.results_text.insert(tk.END, f"{mensagem}\n")
        self.results_text.yview(tk.END)

    def exibir_resultado_em_janela(self, titulo, resultado):
        janela = tk.Toplevel(self.root)
        janela.title(titulo)

        text_area = tk.Text(janela, wrap=tk.WORD, width=80, height=20)
        text_area.insert(tk.END, resultado)
        text_area.pack(padx=10, pady=10)

        btn_fechar = ttk.Button(janela, text="Fechar", command=janela.destroy)
        btn_fechar.pack(pady=5)

    def exportar_csv(self):
        # Obter o conteúdo da área de resultados
        resultados = self.results_text.get(1.0, tk.END)

        # Escolher um local para salvar o arquivo CSV
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])

        # Escrever o conteúdo no arquivo CSV
        with open(file_path, "w", newline="", encoding="utf-8") as csv_file:
            csv_file.write(resultados)

        messagebox.showinfo("Exportação Concluída", "Os resultados foram exportados para um arquivo CSV.")

    def exportar_pdf(self):
        # Obter o conteúdo da área de resultados
        resultados = self.results_text.get(1.0, tk.END)

        # Escolher um local para salvar o arquivo PDF
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])

        # Criar um objeto PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, resultados)

        # Salvar o arquivo PDF
        pdf.output(file_path)

        messagebox.showinfo("Exportação Concluída", "Os resultados foram exportados para um arquivo PDF.")

    def verificar_seguranca(self):
        # Limpar a área de exibição de resultados
        self.results_text.delete(1.0, tk.END)

        # Obter o URL do Entry
        url_alvo = self.entry_url.get()

        # Obtém o código-fonte da página
        codigo_fonte = self.obter_codigo_fonte(url_alvo)
        if codigo_fonte:
            # Realiza a análise de segurança
            self.realizar_analise_seguranca(codigo_fonte)

    def realizar_analise_seguranca(self, codigo_fonte):
        # Avaliação de Criptografia
        self.avaliacao_criptografia(codigo_fonte)

        # Monitoramento de Atividade Suspeita
        logs = self.capturar_logs()
        self.monitoramento_atividade_suspeita(logs)
    def monitoramento_atividade_suspeita(self, logs):
        try:
            # Análise de padrões incomuns nos logs
            compiled_padroes_incomuns = [re.compile(padrao, re.IGNORECASE) for padrao in self.padroes_incomuns]
            for log in logs:
                for compiled_padrao in compiled_padroes_incomuns:
                    if compiled_padrao.search(log):
                        self.exibir_resultado(f"Atividade suspeita detectada nos logs: {log}")

            # Análise de tentativas de exploração
            compiled_tentativas_exploracao = [re.compile(tentativa, re.IGNORECASE) for tentativa in self.tentativas_exploracao]
            for log in logs:
                for compiled_tentativa in compiled_tentativas_exploracao:
                    if compiled_tentativa.search(str(log)):
                        self.exibir_resultado(f"Tentativa de exploração detectada nos logs: {log}")
        except Exception as e:
            self.exibir_resultado(f"Erro no monitoramento de atividade suspeita: {e}")

    def avaliacao_criptografia(self, texto):
        try:
            # Hash SHA-256
            hash_sha256 = hashlib.sha256(texto.encode()).hexdigest()
            self.exibir_resultado(f"Hash SHA-256 do código: {hash_sha256}")
        except Exception as e:
            self.exibir_resultado(f"Erro na avaliação de criptografia: {e}")

    def capturar_logs(self):
        try:
            # Modifique isso de acordo com o seu ambiente e método real para obter logs
            # Aqui, estamos usando o comando "journalctl" no Linux como exemplo
            resultado = subprocess.run(["journalctl", "--no-pager"], capture_output=True, text=True)

            # Verifique se o comando foi executado com sucesso
            if resultado.returncode == 0:
                # Divida as linhas do resultado em uma lista de logs
                logs = resultado.stdout.splitlines()
                return logs
            else:
                # Em caso de erro na execução do comando, exiba uma mensagem
                self.exibir_resultado(f"Erro ao obter logs: {resultado.stderr}")
                return []
        except Exception as e:
            # Lidar com exceções, se houver, durante a execução do método
            self.exibir_resultado(f"Erro ao capturar logs: {e}")
            return []

    def is_admin(self):
        # Verificar se o script está sendo executado como administrador no Windows
        if os.name == 'nt':
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        # Verificar se o script está sendo executado como root no Linux
        elif os.name == 'posix':
            return os.geteuid() == 0
        else:
            return False

    def main(self):
        if self.is_admin():
            # Se já estiver sendo executado como administrador, execute o código principal aqui
            root = tk.Tk()
            app = WebAnalyzerApp(root)
            root.mainloop()
        else:
            messagebox.showerror("Erro", "Esta aplicação requer privilégios de administrador.")
            sys.exit()

if __name__ == "__main__":
    root = tk.Tk()
    app_instance = WebAnalyzerApp(root)
    root.mainloop()
