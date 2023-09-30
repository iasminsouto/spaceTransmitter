import os
import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def generate_rsa_keys(sonda_nome):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    with open(f"{sonda_nome.lower()}.private.pem", "wb") as private_key_file:
        private_key_file.write(private_key)
    
    with open(f"{sonda_nome.lower()}.public.pem", "wb") as public_key_file:
        public_key_file.write(public_key)

def send_public_key_to_certification_server(sonda_nome, server_address, server_port):
    try:
        with open(f"{sonda_nome.lower()}.public.pem", "rb") as public_key_file:
            public_key = public_key_file.read()
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((server_address, server_port))
            client_socket.send(public_key)
            print(f"Chave pública da sonda {sonda_nome} enviada com sucesso para o servidor de certificação.")
    except Exception as e:
        print(f"Erro ao enviar a chave pública: {str(e)}")

def collect_and_encrypt_data(sonda_nome):
    local = input("Local: ")
    temperatura = input("Temperatura: ")
    rad_alpha = input("Radiação Alfa: ")
    rad_beta = input("Radiação Beta: ")
    rad_gamma = input("Radiação Gama: ")

    data = f"Local: {local}\nTemperatura: {temperatura}º\nRadiação Alfa: {rad_alpha}\nRadiação Beta: {rad_beta}\nRadiação Gama: {rad_gamma}"

    key = os.urandom(16) 
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())

    filename = f"{local.replace(' ', '').lower()}.data"
    with open(filename, "wb") as data_file:
        data_file.write(nonce + ciphertext + tag)

    return key 

def generate_signature(filename, sonda_private_key):
    with open(filename, "rb") as data_file:
        data = data_file.read()

    key = RSA.import_key(open(sonda_private_key).read())
    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)

    signature_filename = filename + ".signature"
    with open(signature_filename, "wb") as signature_file:
        signature_file.write(signature)

def send_data_and_signature_to_earth_server(filename, signature_filename, server_address, server_port):
    try:
        with open(filename, "rb") as data_file:
            encrypted_data = data_file.read()

        with open(signature_filename, "rb") as signature_file:
            signature = signature_file.read()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((server_address, server_port))
            client_socket.send(encrypted_data)
            client_socket.send(signature)
            print("Dados e assinatura enviados com sucesso para o servidor da Terra.")
    except Exception as e:
        print(f"Erro ao enviar dados e assinatura: {str(e)}")

def certification_server(certification_port):
    pass

def earth_server(earth_port):
    pass

def main():
    sonda_nome = input("Nome da Sonda: ")
    server_address = "127.0.0.1" 
    certification_port = 5000
    earth_port = 5001
    
    cert_thread = threading.Thread(target=certification_server, args=(certification_port,), daemon=True)
    cert_thread.start()

    earth_thread = threading.Thread(target=earth_server, args=(earth_port,), daemon=True)
    earth_thread.start()
    
    while True:
        print("Opções:")
        print("1 – Cadastrar Sonda e Gerar Par de Chaves")
        print("2 – Enviar Chave da Sonda para Servidor de Certificação")
        print("3 – Coletar Dados da Sonda e Enviar para Servidor da Terra")
        print("4 – Gerar Assinatura dos Dados Coletados")
        print("5 – Sair")
        
        escolha = input("Escolha uma opção: ")
        
        if escolha == "1":
            generate_rsa_keys(sonda_nome)
        elif escolha == "2":
            send_public_key_to_certification_server(sonda_nome, server_address, certification_port)
        elif escolha == "3":
            key = collect_and_encrypt_data(sonda_nome)
            send_data_and_signature_to_earth_server(f"{sonda_nome.lower()}.data", f"{sonda_nome.lower()}.data.signature", server_address, earth_port)
        elif escolha == "4":
            filename = input("Nome do arquivo de dados: ")
            generate_signature(filename, f"{sonda_nome.lower()}.private.pem")
        elif escolha == "5":
            break
        else:
            print("Escolha uma opção válida.")

if __name__ == "__main__":
    main()

