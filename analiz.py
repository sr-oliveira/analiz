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
from PIL import Image
from PIL import ImageTk
import threading
import queue
from tkinter import ttk
import shlex
import platform
from tqdm import tqdm

class WebAnalyzerApp:
    def __init__(self, root):
        self.tempo_limite_metasploit = 220
        self.queue = queue.Queue()
        self.root = root
        root.title("Analiz Web")

        # Caminho do arquivo .ico
        icon_path = os.path.join(os.path.dirname(__file__), 'analiz.ico')

        # Carregar o ícone usando Pillow
        icon = Image.open(icon_path)
        icon = ImageTk.PhotoImage(icon)

        # Definir o ícone da janela principal
        root.tk.call('wm', 'iconphoto', root._w, icon)

        self.padroes_incomuns = ['SQL.*error', 'acesso\s+não\s+autorizado', 'padrão\s+incomum']
        self.tentativas_exploracao = ['DROP\s+TABLE', 'UNION\s+SELECT', 'tentativa\s+de\s+exploração']
        self.modulos_metasploit = [
            "exploit/multi/sql/sql_injection",
            "exploit/multi/http/xss_module",
            "exploit/multi/http/command_injection",
            "auxiliary/scanner/http/dir_scanner",
            "exploit/multi/http/rails_vuln_module",
            # Adicione mais módulos conforme necessário
        ]
        self.create_widgets()

    def create_widgets(self):
        # Quadro para funções principais
        frame_funcoes_principais = ttk.LabelFrame(self.root, text="Funções Principais")
        frame_funcoes_principais.grid(column=0, row=0, padx=10, pady=5, sticky=tk.W)

        self.label_url = ttk.Label(frame_funcoes_principais, text="URL Alvo:")
        self.label_url.grid(column=0, row=0, padx=10, pady=5, sticky=tk.W)

        self.entry_url = ttk.Entry(frame_funcoes_principais, width=50)
        self.entry_url.insert(0, 'https://exemplo.com/')
        self.entry_url.grid(column=1, row=0, padx=10, pady=5, sticky=tk.W)

        self.btn_analisar = ttk.Button(frame_funcoes_principais, text="Analisar 🕵️", command=self.analisar)
        self.btn_analisar.grid(column=2, row=0, padx=10, pady=5)

        self.btn_descompilar_js = ttk.Button(frame_funcoes_principais, text="Descompilar JS 📜", command=self.descompilar_js)
        self.btn_descompilar_js.grid(column=3, row=0, padx=10, pady=5)

        self.btn_verificar_seguranca = ttk.Button(frame_funcoes_principais, text="Verificar Segurança 🔒", command=self.verificar_seguranca)
        self.btn_verificar_seguranca.grid(column=4, row=0, padx=10, pady=5)

    # Área de exibição de resultados
        self.results_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=20)
        self.results_text.grid(column=0, row=1, padx=10, pady=5, sticky="nsew", columnspan=5)

    # Quadro para exportação e comandos Metasploit
        frame_exportacao_metasploit = ttk.LabelFrame(self.root, text="Exportação e Metasploit")
        frame_exportacao_metasploit.grid(column=5, row=0, padx=10, pady=5, sticky=tk.W+tk.E+tk.N+tk.S)

        self.btn_exportar_csv = ttk.Button(frame_exportacao_metasploit, text="Exportar CSV 📊", command=self.exportar_csv)
        self.btn_exportar_csv.grid(column=0, row=0, padx=10, pady=5)

        self.btn_exportar_pdf = ttk.Button(frame_exportacao_metasploit, text="Exportar PDF 📄", command=self.exportar_pdf)
        self.btn_exportar_pdf.grid(column=1, row=0, padx=10, pady=5)

        self.btn_abrir_terminal = ttk.Button(frame_exportacao_metasploit, text="Abrir Metasploit Console 🚀", command=self.abrir_terminal_metasploit)
        self.btn_abrir_terminal.grid(column=2, row=0, padx=10, pady=5)

    # Adicione uma label para mostrar o status de instalação
        self.label_status_instalacao = ttk.Label(self.root, text="")
        self.label_status_instalacao.grid(column=5, row=1, padx=10, pady=5)

    # Adicione um botão para instalar o Metasploit
        self.btn_instalar_metasploit = ttk.Button(frame_exportacao_metasploit, text="Instalar Metasploit 🔄", command=self.instalar_metasploit)
        self.btn_instalar_metasploit.grid(column=0, row=1, padx=10, pady=5, columnspan=3)

    # Verifique e atualize o status de instalação
        self.verificar_status_instalacao_metasploit()

    # Configuração de peso para tornar os widgets expansíveis
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        frame_funcoes_principais.columnconfigure(1, weight=1)
        frame_exportacao_metasploit.columnconfigure(2, weight=1)


        self.progress_bar = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress_bar.grid(column=0, row=2, columnspan=7, padx=10, pady=5)

    def exibir_resultado(self, mensagem):
        self.results_text.insert(tk.END, f"{mensagem}\n")
        self.results_text.yview(tk.END)

    def verificar_seguranca(self):
        # Limpar a área de exibição de resultados
        self.results_text.delete(1.0, tk.END)

        # Obter o URL do Entry
        url_alvo = self.entry_url.get()

        # Exibir barra de carregamento indeterminada
        self.progress_bar["mode"] = "indeterminate"
        self.progress_bar.start()

        # Iniciar a verificação de segurança em uma thread separada
        self.root.after(100, lambda: self.realizar_analise_seguranca_thread(url_alvo))

    def realizar_analise_seguranca_thread(self, url_alvo):
        try:
            # Obtém o código-fonte da página
            codigo_fonte = self.obter_codigo_fonte(url_alvo)
            if codigo_fonte:
                # Realiza a análise de segurança
                self.realizar_analise_seguranca(codigo_fonte, url_alvo)

        finally:
            # Parar a barra de carregamento indeterminada
            self.progress_bar.stop()
            self.progress_bar.grid_forget()
    def analisar(self):
        # Limpar a área de exibição de resultados
        self.results_text.delete(1.0, tk.END)

        # Obter o URL do Entry
        url_alvo = self.entry_url.get()

        # Adicionar feedback de processamento
        self.exibir_resultado("Iniciando análise. Isso pode levar algum tempo, por favor, aguarde...")

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

            # Adicionar feedback de conclusão
            self.exibir_resultado("Análise concluída.")

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
            # Adicionar manuseio de erros
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
            # Adicionar manuseio de erros
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
            # Adicionar manuseio de erros
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

    

    def realizar_analise_seguranca(self, codigo_fonte, url_alvo):
        # Avaliação de Criptografia
        self.avaliacao_criptografia(codigo_fonte)

        # Monitoramento de Atividade Suspeita
        logs = self.capturar_logs()
        self.monitoramento_atividade_suspeita(logs)

        # Verificação de Vulnerabilidades com Metasploit
        self.verificar_vulnerabilidades_metasploit(url_alvo)

    def verificar_vulnerabilidades_metasploit(self, url_alvo):
        try:
            # Exibir barra de carregamento indeterminada para a verificação de vulnerabilidades
            self.progress_bar["mode"] = "indeterminate"
            self.progress_bar.start()

            # Iniciar a verificação de vulnerabilidades
            for modulo in self.modulos_metasploit:
                # Construir o comando Metasploit de forma mais segura
                comando_metasploit = f'msfconsole -x "use {shlex.quote(modulo)}; set RHOSTS {shlex.quote(url_alvo)}; exploit"'

                self.exibir_resultado(f"Executando comando Metasploit: {comando_metasploit}")

                # tempo limite 3 minutos
                resultado_metasploit = subprocess.run(comando_metasploit, shell=True, capture_output=True, text=True, timeout=180)

                # Adicionar resultado à fila para exibição na interface principal
                self.queue.put((modulo, resultado_metasploit))

                # Verificar se a vulnerabilidade foi explorada com sucesso
                if re.search(r'Successfully exploited', resultado_metasploit.stdout):
                    self.exibir_resultado(f"Vulnerabilidade explorada com sucesso no módulo {modulo}!")

            # Parar a barra de carregamento indeterminada
            self.progress_bar.stop()
            self.progress_bar.grid_forget()

        except subprocess.TimeoutExpired:
            self.exibir_resultado("Tempo limite expirado durante a inicialização do Metasploit.")
        except Exception as e:
            self.exibir_resultado(f"Erro ao aguardar o Metasploit carregar: {e}")


    def abrir_terminal_metasploit(self):
        try:
            self.exibir_resultado("Abrindo Metasploit Console no terminal...")

            # Comando para iniciar o Metasploit Console
            comando_metasploit_console = 'msfconsole'

            # Abrir o terminal para o Metasploit Console
            subprocess.run(comando_metasploit_console, shell=True)

            self.exibir_resultado("Metasploit Console encerrado.")

        except Exception as e:
            self.exibir_resultado(f"Erro ao abrir o Metasploit Console: {e}")



    def monitoramento_atividade_suspeita(self, logs):
        # Padrão para identificar explorações bem-sucedidas
        padrao_exploracao = re.compile(r'Successfully exploited', re.IGNORECASE)

        # Lista para armazenar eventos de atividade suspeita
        atividades_suspeitas = []

        # Analisar logs em busca de padrões específicos
        for log in logs:
            if padrao_exploracao.search(log):
                atividades_suspeitas.append("Detetada exploração bem-sucedida: " + log)

        # Exibir resultados na área de resultados
        if atividades_suspeitas:
            self.exibir_resultado("Atividades Suspeitas Detectadas:")
            for atividade in atividades_suspeitas:
                self.exibir_resultado(atividade)
        else:
            self.exibir_resultado("Nenhuma atividade suspeita detectada.")

        self.exibir_resultado("Monitoramento de atividade suspeita concluído.")

    def avaliacao_criptografia(self, texto):
        try:
            # Hash SHA-256
            hash_sha256 = hashlib.sha256(texto.encode()).hexdigest()
            self.exibir_resultado(f"Hash SHA-256 do código: {hash_sha256}")
        except Exception as e:
            self.exibir_resultado(f"Erro na avaliação de criptografia: {e}")
    


    def verificar_status_instalacao_metasploit(self):
        try:
            # Verificar o sistema operacional
            sistema_operacional = platform.system().lower()

            # Se o sistema operacional for Linux
            if sistema_operacional == "linux":
                # Verificar se o Metasploit está instalado
                comando_verificacao = "which msfconsole"
                resultado_verificacao = subprocess.run(comando_verificacao, shell=True, capture_output=True, text=True)

                if resultado_verificacao.returncode == 0:
                    self.label_status_instalacao.config(text="Metasploit já está instalado.")
                    self.btn_instalar_metasploit.grid_forget()  # Esconda o botão de instalação

                else:
                    self.label_status_instalacao.config(text="Metasploit não está instalado.")
                    self.btn_instalar_metasploit.grid(column=7, row=0, padx=10, pady=5)

            else:
                # Se não for Linux, não exiba o botão de instalação
                self.label_status_instalacao.config(text="Instalação suportada apenas no Linux.")
                self.btn_instalar_metasploit.grid_forget()

        except Exception as e:
            self.exibir_resultado(f"Erro ao verificar o status de instalação do Metasploit: {e}")

    def instalar_metasploit(self):
        try:
            self.exibir_resultado("Iniciando a instalação do Metasploit...")

            # Construa o comando de instalação do Metasploit
            comando_instalacao_metasploit = "curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/" \
                                            "master/config/templates/metasploit-framework-wrappers/msfupdate.erb " \
                                            "> msfinstall && chmod 755 msfinstall && ./msfinstall"

            # Execute o comando
            resultado_instalacao = subprocess.run(comando_instalacao_metasploit, shell=True, capture_output=True, text=True)

            # Exiba o resultado na área de resultados
            self.exibir_resultado(f"Resultado da instalação:\n{resultado_instalacao.stdout}")

            # Verifique se a instalação foi bem-sucedida
            if resultado_instalacao.returncode == 0:
                self.exibir_resultado("Metasploit instalado com sucesso!")
                self.label_status_instalacao.config(text="Metasploit já está instalado.")
                self.btn_instalar_metasploit.grid_forget()  # Esconda o botão de instalação
            else:
                self.exibir_resultado(f"Erro durante a instalação: {resultado_instalacao.stderr}")

        except Exception as e:
            self.exibir_resultado(f"Erro ao instalar o Metasploit: {e}")

    def capturar_logs(self):
        try:
            resultado = subprocess.run(["journalctl", "--no-pager"], capture_output=True, text=True)
        
            if resultado.returncode == 0:
                logs = resultado.stdout.splitlines()
                return logs
            else:
                self.exibir_resultado(f"Erro ao obter logs: {resultado.stderr}")
                return []
        except Exception as e:
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

