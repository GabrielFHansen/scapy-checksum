from scapy.all import sniff, IP
from datetime import datetime

def calcular_checksum_manual(ip_bytes):
    total = 0
    print("Calculando checksum manualmente...")

    for i in range(0, 20, 2):  # Apenas os primeiros 20 bytes (cabeçalho fixo)
        if i == 10:
            word = 0  # Zera o campo de checksum durante o cálculo
        else:
            word = (ip_bytes[i] << 8) + ip_bytes[i + 1]
        total += word
        print(f"Bytes {i}-{i+1}: 0x{word:04x} | Soma Parcial: 0x{total:05x}")

    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
        print(f"Carry aplicado: Soma Corrigida: 0x{total:04x}")

    checksum = ~total & 0xFFFF
    print(f"Checksum final: 0x{checksum:04x}\n")
    return checksum

def analisar_pacote(pkt, idx):
    if IP in pkt:
        ip_layer = pkt[IP]
        raw_ip = bytes(ip_layer)[:20]  # Cabeçalho IPv4 fixo

        original = ip_layer.chksum
        print(f"\nPacote {idx} ----------------------")
        print(f"Origem: {ip_layer.src} -> Destino: {ip_layer.dst}")
        print(f"Protocolo: {ip_layer.proto}, TTL: {ip_layer.ttl}")
        print(f"Checksum original no pacote: 0x{original:04x}")

        recalculado = calcular_checksum_manual(raw_ip)
        status = "VÁLIDO" if original == recalculado else "INVÁLIDO"

        log = f"{datetime.now()} - {ip_layer.src} -> {ip_layer.dst} - {ip_layer.proto} - {status}"
        print("STATUS:", status)
        with open("ip_checksum.log", "a") as f:
            f.write(log + "\n")

# Captura ao vivo
print("🟢 Capturando pacotes ao vivo... Pressione Ctrl+C para parar.\n")
sniff(filter="ip", prn=lambda x: analisar_pacote(x, x.time), store=False)
