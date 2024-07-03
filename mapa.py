import google_maps
import requests
from bs4 import BeautifulSoup

# Pesquisa empresas no Google Maps
empresas = google_maps.query_places(query=["empresas em Goiânia"])

# Abre um arquivo CSV para salvar as informações
with open("empresas_goiania.csv", "w", encoding="utf-8") as csvfile:
    # Escreve o cabeçalho da tabela CSV
    csvfile.write("Nome,Endereço,Telefone,Link,Link Compartilhamento\n")

    # Itera sobre cada empresa nos resultados
    for empresa in empresas.places:
        # Extrai as informações da empresa
        nome = empresa.name
        link = empresa.url
        telefone = empresa.phone_number

        # Busca o endereço completo da empresa
        endereco_completo = google_maps.get_place_details(place_id=empresa.place_id)["formatted_address"]

        # Abre a página da empresa no navegador
        pyautogui.hotkey("ctrl", "t")  # Abre nova aba
        pyautogui.write(link)
        pyautogui.press("enter")

        # Extrai o link de compartilhamento (se disponível)
        link_compartilhamento = None
        try:
            # Simula um clique no botão de compartilhamento (código depende do site)
            pyautogui.click(x=100, y=100)  # Substitua com as coordenadas reais do botão

            # Extrai o link da página após o clique no botão de compartilhamento
            page_source = requests.get(link).content
            soup = BeautifulSoup(page_source, "html.parser")
            link_compartilhamento = soup.find("a", {"href": lambda href: href and "compartilhar" in href})["href"]
        except:
            pass  # Ignora se o link de compartilhamento não for encontrado

        # Salva as informações da empresa no CSV
        csvfile.write(f"{nome},{endereco_completo},{telefone},{link},{link_compartilhamento}\n")

        # Fecha a aba do navegador
        pyautogui.hotkey("ctrl", "w")
