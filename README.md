# Analisador de Checksum IPv4 em Pacotes `.pcap`

Este projeto tem como objetivo **analisar e validar pacotes de rede** do protocolo **IPv4** a partir de arquivos `.pcap`, realizando o **cálculo manual do checksum** do cabeçalho IP — sem utilizar o parser automático do Scapy — em conformidade com a disciplina de Redes de Computadores.

---

## 💡 Objetivo

Validar a integridade dos pacotes IP por meio da verificação do campo de **checksum do cabeçalho IPv4**, realizando:

- Extração **manual** dos campos do cabeçalho IP;
- Cálculo do checksum conforme especificação do **RFC 791**;
- Comparação entre o checksum recalculado e o valor original armazenado;
- Geração de logs com o **status** de cada pacote (`VÁLIDO` ou `INVÁLIDO`).

---

## 📦 Dependências

- Python 3.x
- [Scapy](https://scapy.net/) (usado apenas para abrir arquivos `.pcap`)

Instalação via `pip`:

```bash
pip install scapy
```

## ⚙️ Funcionamento do Código

Funções principais:
**parse_ipv4_header(pkt_bytes)**
Lê os 20 primeiros bytes do cabeçalho IPv4 e interpreta manualmente os seguintes campos:

- Versão e IHL

- Tamanho total

- Identificação

- Flags e Offset

- TTL e Protocolo

- Checksum

- Endereço IP de origem e destino


**calcular_checksum_manual(ip_header_bytes)**

Calcula manualmente o checksum do cabeçalho IPv4:

- Zera o campo de checksum (bytes 10 e 11);

- Divide o cabeçalho em palavras de 16 bits (2 bytes);

- Soma todas as palavras com controle de overflow (carry);

 - Realiza o complemento de 1 do resultado.

 📌 Este processo simula o comportamento de roteadores e hosts ao verificar a integridade do cabeçalho IP.

 **analisar_pacote(pkt, indice)**

 Para cada pacote lido do `.pcap`, extrai o cabeçalho IP bruto, executa `parse_ipv4_header`, chama `calcular_checksum_manual` e imprime o status.


 📋 Exemplo de Saída

```bash
Pacote 8459 ----------------------
Origem: 192.168.0.103 -> Destino: 3.162.247.33
Protocolo: 6, TTL: 128
Checksum original no pacote: 0xdafa
Calculando checksum manualmente...
Bytes 0-1: 0x45b8 | Soma Parcial: 0x45b8
Bytes 2-3: 0x0028 | Soma Parcial: 0x45e0
...
Checksum final: 0xdafa
STATUS: VÁLIDO
```

🧪 Como Usar
1. Coloque seu arquivo .pcap capturado com o Wireshark na raiz do projeto.

2. Execute o script:

```bash
python analisador_checksum.py
```

3. O status de cada pacote será exibido no terminal e registrado em `ip_checksum.log`.

🧠 Considerações Técnicas
- O campo checksum IP cobre apenas o cabeçalho (20 bytes padrão).

- Campos opcionais (extensões de cabeçalho) não são tratados.

- Pacotes sem cabeçalho IPv4 válido são ignorados.

- O projeto não depende da interpretação automática do Scapy — o cabeçalho é manipulado diretamente como sequência de bytes.


🐳 Execução via Docker

Você pode executar o analisador de checksum em um ambiente isolado, sem necessidade de instalar dependências localmente.

Montar imagem docker com

```bash
docker build -t checksum-analisador .
```

 Execute o contêiner com o .pcap montado

 Assumindo que seu arquivo `local.pcap` está na mesma pasta:

 ```bash
 docker run --rm -v $(pwd):/app checksum-analisador
 ```