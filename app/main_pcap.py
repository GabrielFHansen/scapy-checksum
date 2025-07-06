from scapy.all import rdpcap
import struct
import socket


def parse_ipv4_header(raw_bytes):
    if len(raw_bytes) < 20:
        return None

    header = struct.unpack('!BBHHHBBH4s4s', raw_bytes[:20])

    version_ihl     = header[0]
    version         = version_ihl >> 4
    ihl             = version_ihl & 0x0F
    tos             = header[1]
    total_length    = header[2]
    identification  = header[3]
    flags_frag      = header[4]
    ttl             = header[5]
    protocol        = header[6]
    checksum        = header[7]
    src_ip          = socket.inet_ntoa(header[8])
    dst_ip          = socket.inet_ntoa(header[9])

    return {
        "versao": version,
        "ihl": ihl,
        "tos": tos,
        "tamanho_total": total_length,
        "id": identification,
        "flags_fragmento": flags_frag,
        "ttl": ttl,
        "protocolo": protocol,
        "checksum": checksum,
        "origem": src_ip,
        "destino": dst_ip,
        "raw_header": raw_bytes[:20]  # necessário para o checksum
    }

def calcular_checksum_manual(header_bytes):
    total = 0
    print("Calculando checksum manualmente...")
    for i in range(0, len(header_bytes), 2):
        # Tratar último byte ímpar (teoricamente não ocorre no cabeçalho IP, mas é boa prática)
        if i + 1 < len(header_bytes):
            word = (header_bytes[i] << 8) + header_bytes[i + 1]
        else:
            word = (header_bytes[i] << 8)
        total += word
        print(f"Bytes {i}-{i+1}: {word:#06x} | Soma Parcial: {total:#06x}")

    # Adicionar carry (overflow além de 16 bits)
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
        print(f"Carry aplicado: Soma Corrigida: {total:#06x}")

    checksum = ~total & 0xFFFF  # complemento de 1
    print(f"Checksum final: {checksum:#06x}\n")
    return checksum

# Carrega os pacotes do arquivo .pcap
pkts = rdpcap("local.pcap")

for i, pkt in enumerate(pkts):
    raw = bytes(pkt)
    if len(raw) >= 34:  # Ethernet (14) + IP (20)
        ip_header = raw[14:34]
        campos = parse_ipv4_header(ip_header)
        if campos:
            print(f"\nPacote {i+1} ----------------------")
            print(f"Origem: {campos['origem']} -> Destino: {campos['destino']}")
            print(f"Protocolo: {campos['protocolo']}, TTL: {campos['ttl']}")
            print(f"Checksum original no pacote: {campos['checksum']:#06x}")
            
            # Zera o campo de checksum antes do cálculo
            header_bytes = bytearray(campos["raw_header"])
            header_bytes[10] = 0
            header_bytes[11] = 0

            checksum_calc = calcular_checksum_manual(header_bytes)

            status = "VÁLIDO" if checksum_calc == campos["checksum"] else "INVÁLIDO"
            print(f"STATUS: {status}")
