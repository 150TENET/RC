# Redes de Computadores (Trabalho Prático 2 - Packet Sniffer)
- a109749 - Gabriel Andrade Teodoro
- a112407 - Joana Catarina Fernandes Rodrigues 
- a110565 - Luís Mário Teixeira Lemos

---
 
## Dependências
 
| Biblioteca | Versão mínima | Finalidade |
|------------|--------------|------------|
| `scapy` | 2.5+ | Captura e dissecção de pacotes |
| `python` | 3.10+ | Linguagem base |
 
**Instalação das dependências:**
 
```bash
pip install -r requirements.txt
```
 
> **Nota:** a captura de pacotes requer privilégios de root/administrador.
 
---
 
## Como Selecionar a Interface
 
A interface de rede é um argumento **obrigatório**, passado com `-i` ou `--interface`.
 
```bash
sudo python3 sniffer.py -i <INTERFACE>
```
 
**Exemplos:**
 
```bash
# Interface ethernet
sudo python3 sniffer.py -i eth0
 
# Interface Wi-Fi
sudo python3 sniffer.py -i wlan0
 
# Interface de loopback
sudo python3 sniffer.py -i lo
```
 
 
---
 
## Como Ativar Filtros
  
### Filtro BPF (Berkeley Packet Filter)
 
Filtragem de baixo nível passada diretamente ao Scapy. Usa a flag `-f` ou `--filter`.
 
```bash
# Capturar apenas tráfego ICMP
sudo python3 sniffer.py -i eth0 -f "icmp"
 
# Capturar apenas tráfego de/para um host específico
sudo python3 sniffer.py -i eth0 -f "host 192.168.1.1"
 
# Capturar apenas tráfego na porta 443
sudo python3 sniffer.py -i eth0 -f "port 443"
```
 
### Filtro por Protocolo
 
Filtra os pacotes por protocolo já após a captura. Usa a flag `-p` ou `--protocol`. **Repetível** para incluir múltiplos protocolos.
 
```bash
# Apenas ICMP
sudo python3 sniffer.py -i eth0 -p ICMP
 
# ICMP e ARP em simultâneo
sudo python3 sniffer.py -i eth0 -p ICMP -p ARP
```
 
Protocolos suportados: `TCP`, `UDP`, `ICMP`, `ARP`, `DNS`, `IPv4`
 
### Filtro por Endereço IP
 
Mostra apenas pacotes com o IP especificado como origem ou destino. Usa a flag `--ip`.
 
```bash
sudo python3 sniffer.py -i eth0 --ip 192.168.1.100
```
 
### Filtro por Endereço MAC
 
Mostra apenas pacotes com o MAC especificado como origem ou destino. Usa a flag `--mac`.
 
```bash
sudo python3 sniffer.py -i eth0 --mac aa:bb:cc:dd:ee:ff
```
 
---
 
## Funcionalidades Implementadas
 
### Captura de Pacotes
- Captura em tempo real sobre qualquer interface de rede disponível no sistema
- Suporte a filtros BPF nativos para filtragem
- Limitação do número de pacotes com `-c` / `--count` (0 = ilimitado)
- Gravação da captura num ficheiro `.pcap` com `-w` / `--write`, compatível com Wireshark

### Parsing de Protocolos
Cada protocolo tem um parser dedicado que extrai e formata os campos relevantes:
 
| Protocolo | Informação extraída |
|-----------|-------------------|
| **TCP** | IPs, portas (com nomes para portas conhecidas), flags (SYN/ACK/FIN/RST/PSH/URG/ECE/CWR), seq, ack, window, tamanho do payload, interpretação do handshake |
| **UDP** | IPs, portas (com nomes para portas conhecidas, incluindo QUIC), tamanho do payload |
| **ICMP** | IPs, tipo (Echo Request/Reply, TTL Exceeded), código, id, seq |
| **ARP** | Operação (Request/Reply), MACs e IPs de emissor e destinatário, formato "Who has X? Tell Y" |
| **DNS** | Query vs. Response, nome do domínio, tipo de record (A, AAAA, CNAME, MX, etc.), transaction ID, respostas (até 3 mostradas) |
| **IPv4** | IPs, protocolo de transporte, TTL, ID, flags IP (DF/MF), deteção e offset de fragmentos |
 
### Output em Tempo Real
- Apresentação colorida no terminal por protocolo (TCP=verde, UDP=amarelo, ICMP=ciano, ARP=magenta, DNS=azul, IPv4=vermelho)
- Pode ser desativado com `--no-live` (útil para capturar apenas para ficheiro)
- Cabeçalho com colunas alinhadas: `DATA/HORA | IFACE | PROTO | TAMANHO | DETALHE`
### Logging para Ficheiro
Exportação do tráfego capturado com `-l` / `--log`, em três formatos selecionáveis com `--log-format`:
 
```bash
# Log em texto simples (default)
sudo python3 sniffer.py -i eth0 -l captura.txt --log-format txt
 
# Log em CSV (importável em Excel, pandas, etc.)
sudo python3 sniffer.py -i eth0 -l captura.csv --log-format csv
 
# Log em JSON (um objeto por pacote)
sudo python3 sniffer.py -i eth0 -l captura.json --log-format json
```
 
Campos exportados: `timestamp`, `interface`, `protocol`, `length`, `src_mac`, `dst_mac`, `src_ip`, `dst_ip`, `summary`
 
### Estatísticas Finais
No fim de cada sessão (Ctrl+C ou limite de pacotes atingido), é apresentado automaticamente um resumo com a contagem e percentagem por protocolo.
 
---
 
## Como Correr
 
### No PC (Linux)
 
**1. Instalação:**
 
```bash
pip install scapy
```
 
**2. Execução básica:**
 
```bash
sudo python3 sniffer.py -i eth0
```
 
**3. Exemplos completos:**
 
```bash
# Capturar 100 pacotes TCP/UDP, guardar em pcap e log CSV
sudo python3 sniffer.py -i eth0 -p TCP -p UDP -c 100 -w captura.pcap -l log.csv --log-format csv
 
# Monitorizar tráfego DNS e filtrar por host
sudo python3 sniffer.py -i wlan0 -f "port 53" -p DNS -l dns.json --log-format json
 
# Captura silenciosa (sem output no terminal) para ficheiro
sudo python3 sniffer.py -i eth0 --no-live -w captura.pcap
```
 
> **Nota:** se surgir `Operation not permitted`, certifica-te de que estás a correr com `sudo`.
 
---
 
### No CORE 
 
**Instalar a dependência no nó:**
 
```bash
pip install scapy
```
 
**Verificar as interfaces disponíveis no nó:**
 
```bash
ip link show
```
 
**Executar o sniffer:**
 
```bash
# Capturar todo o tráfego na interface eth0 do nó
python3 sniffer.py -i eth0
 
# Monitorizar tráfego entre dois nós específicos
python3 sniffer.py -i eth0 --ip 10.0.0.2
 
# Guardar captura para analisar depois no Wireshark
python3 sniffer.py -i eth0 -w captura_core.pcap
```
 
**Abrir o `.pcap` no Wireshark (fora do CORE):**
 
```bash
wireshark captura_core.pcap
```
 
---
 
## Resumo dos Argumentos Disponíveis
 
| Argumento | Abreviatura  | Descrição |
|-----------|-------------|-----------|
| `--interface` | `-i` | Interface de rede para captura |
| `--filter` | `-f` | Filtro BPF (ex: `"host 10.0.0.1"`, `"icmp"`) |
| `--count` | `-c`  | Nº de pacotes a capturar (default: 0 = ilimitado) |
| `--protocol` | `-p`  | Filtrar por protocolo (repetível) |
| `--ip` |  | Filtrar por endereço IP |
| `--mac` | | Filtrar por endereço MAC |
| `--write` | `-w`  | Guardar captura em ficheiro `.pcap` |
| `--log` | `-l`  | Ficheiro de log (txt/csv/json) |
| `--log-format` |  | Formato do log: `txt`, `csv`, `json` (default: `txt`) |
| `--no-live` |  | Desativar output em tempo real no terminal |

