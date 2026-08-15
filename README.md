# ORFX — Offensive Recon Framework

**Framework modular de reconhecimento para avaliações de segurança autorizadas.**

`Python 3.10+` · `Bash` · `CLI simples` · `JSON / TXT / HTML`

> Desenvolvido para laboratórios, ambientes internos e ativos que você possui ou está explicitamente autorizado a testar.

---

## Sobre

O **ORFX (Offensive Recon Framework)** é um toolkit leve de reconhecimento desenvolvido em Python e Bash.

O objetivo é concentrar tarefas comuns de reconhecimento em uma interface CLI simples, mantendo os resultados organizados e correlacionados em um único modelo de ativos.

Principais capacidades:

* Descoberta de domínios e subdomínios
* Resolução IPv4 e IPv6
* Enumeração DNS
* Probing HTTP/HTTPS
* Identificação básica de tecnologias
* Inspeção TLS e certificados
* Descoberta de portas TCP
* Coleta limitada de banners
* Consultas WHOIS
* Correlação de resultados
* Geração de relatórios estruturados

O ORFX **não implementa exploração, ataques de credenciais, persistência ou ações destrutivas**.

---

## Requisitos

Sistemas suportados:

* Kali Linux
* Debian
* Ubuntu
* WSL2
* Outros sistemas Linux com Python 3.10+ e Bash

Requisitos principais:

```text
Python 3.10+
Bash
Acesso de rede
```

Ferramentas recomendadas:

```bash
sudo apt update
sudo apt install dnsutils whois -y
```

`nmap` é opcional e pode ser utilizado para validação independente dos resultados.

---

## Instalação

```bash
git clone https://github.com/NeiveZ/Offensive-Recon-Framework.git
cd Offensive-Recon-Framework

chmod +x orfx.sh

./orfx.sh --install
./orfx.sh --check
```

O instalador utiliza um ambiente Python isolado em `.venv`.

---

## Primeiros comandos

Consultar ajuda:

```bash
./orfx.sh --help
```

Verificar o ambiente:

```bash
./orfx.sh --check
```

Executar módulos individuais:

```bash
./orfx.sh dns -d example.com
./orfx.sh http -u https://example.com
./orfx.sh tls -d example.com
./orfx.sh subdomains -d example.com --resolve
./orfx.sh ports -t example.com --ports top100
./orfx.sh whois -d example.com
```

---

## Comandos principais

### Subdomains

Descoberta baseada em fontes passivas e wordlists:

```bash
./orfx.sh subdomains -d example.com --resolve
```

Perfis disponíveis:

```bash
./orfx.sh subdomains -d example.com --profile fast
./orfx.sh subdomains -d example.com --profile balanced
./orfx.sh subdomains -d example.com --profile accurate
```

---

### DNS

```bash
./orfx.sh dns -d example.com
```

Selecionar registros:

```bash
./orfx.sh dns -d example.com --records A,AAAA,MX,NS,TXT,SOA,CAA
```

---

### HTTP / HTTPS

```bash
./orfx.sh http -u https://example.com
```

Também é possível trabalhar com múltiplos alvos:

```bash
./orfx.sh http -i reports/example_subdomains.txt
```

O módulo coleta informações como:

* Status HTTP
* URL final
* Headers
* Tecnologias básicas
* Security headers
* Erros de conexão

---

### TCP Ports

Portas específicas:

```bash
./orfx.sh ports -t example.com --ports 22,80,443,8080
```

Intervalo:

```bash
./orfx.sh ports -t example.com --ports 1-1024
```

Conjunto comum:

```bash
./orfx.sh ports -t example.com --ports top100
```

---

### TLS

```bash
./orfx.sh tls -d example.com
```

O módulo analisa:

* Protocolo TLS
* Cipher negociado
* Certificado
* Emissor
* Validade
* SANs
* Resultado da verificação

---

### WHOIS

```bash
./orfx.sh whois -d example.com
```

---

## Full Reconnaissance

O comando `full` integra os principais módulos em um único fluxo:

```bash
./orfx.sh full -d example.com --resolve
```

Com descoberta de portas:

```bash
./orfx.sh full -d example.com --resolve --ports top100
```

Pipeline:

```text
Target
  |
  +-- Subdomain Discovery
  |
  +-- DNS Enumeration
  |
  +-- HTTP/HTTPS Probing
  |
  +-- TLS Inspection
  |
  +-- Optional Port Discovery
  |
  +-- Correlation Engine
  |
  +-- Unified Report
```

`auto` é um alias para `full`:

```bash
./orfx.sh auto -d example.com
```

---

## User-Agent

O ORFX permite definir ou alternar o `User-Agent` das requisições HTTP.

Valor personalizado:

```bash
./orfx.sh http -u https://example.com \
  --user-agent "Mozilla/5.0 (compatible; SecurityAssessment/3.2)"
```

Rotação:

```bash
./orfx.sh http -u https://example.com --user-agent random
```

Arquivo personalizado:

```bash
./orfx.sh http -u https://example.com \
  --user-agent @/path/to/user-agents.txt
```

A funcionalidade altera somente o header `User-Agent`.

---

## Correlação de Resultados

O ORFX transforma os resultados dos módulos em um modelo unificado contendo:

```text
Target
Assets
DNS
Subdomains
HTTP Services
Open Ports
TLS Services
WHOIS
Findings
Errors
Summary
```

O objetivo é conectar informações já coletadas, sem inventar novos achados.

---

## Relatórios

Os resultados podem ser exportados em três formatos:

```bash
--json
--txt
--html
```

Exemplo:

```bash
./orfx.sh full \
  -d example.com \
  --resolve \
  --json \
  --html \
  --out reports/example_full
```

Saída:

```text
reports/example_full.json
reports/example_full.html
```

Formatos:

| Formato | Uso                                 |
| ------- | ----------------------------------- |
| JSON    | Automação e processamento posterior |
| TXT     | Revisão rápida e arquivamento       |
| HTML    | Apresentação e análise em navegador |

---

## Normalized Findings

Os módulos convertem os resultados para uma estrutura comum:

```json
{
  "severity": "INFO",
  "target": "example.com",
  "check": "HTTP status",
  "detail": "200"
}
```

Severidades utilizadas:

```text
INFO
LOW
WARN
HIGH
ERROR
```

Essas classificações são auxiliares de relatório e não substituem análise manual ou ferramentas especializadas.

---

## Arquitetura

```text
ORFX/
├── orfx.py
├── orfx.sh
├── core/
├── modules/
├── utils/
├── tests/
├── config/
├── reports/
├── requirements.txt
├── SECURITY.md
├── ETHICS.md
├── CHANGELOG.md
└── README.md
```

Principais componentes:

```text
core/       → correlação, pipeline e configurações
modules/    → DNS, HTTP, portas, subdomínios, TLS e WHOIS
utils/      → utilitários e gerenciamento de sessão
tests/      → testes automatizados
config/     → configurações
reports/    → resultados das execuções
```

---

## Performance e Controle

O ORFX utiliza:

* Concorrência controlada
* Timeouts configuráveis
* Retries
* Perfis de varredura
* Limites internos de workers

Perfis de subdomínio:

| Perfil     | Threads | Timeout | Retries |
| ---------- | ------: | ------: | ------: |
| `fast`     |      30 |      2s |       1 |
| `balanced` |      15 |      3s |       2 |
| `accurate` |       5 |      5s |       3 |

Aumentar threads não significa necessariamente maior precisão. Wordlist, retries, timeout e comportamento do resolver também influenciam a cobertura.

---

## Testes

Os testes ficam em `tests/`.

Com `pytest` instalado:

```bash
python3 -m pytest -q
```

O projeto mantém testes para componentes como:

* Normalização de domínio
* Parsing de portas
* HTTP
* TLS
* Correlação de resultados

---

## Filosofia

O ORFX foi desenvolvido com foco em:

**Simplicidade**

Uma CLI única para tarefas comuns de reconhecimento.

**Modularidade**

Cada função principal é isolada em módulos independentes.

**Rastreabilidade**

Resultados e falhas são preservados nos relatórios.

**Controle**

Concorrência, timeout e profundidade de descoberta permanecem configuráveis.

**Correlação**

Os resultados dos diferentes módulos são apresentados como um único modelo de ativos.

---

## Escopo e Limitações

O ORFX é um framework de **reconhecimento**, não uma plataforma completa de exploração.

Não pretende substituir:

* Ferramentas completas de vulnerability scanning
* Frameworks de exploração
* Plataformas de password testing
* Crawlers avançados
* Scanners especializados

Seu objetivo é oferecer uma base leve e organizada para descoberta, enumeração e correlação de informações.

---

## Uso Responsável

Use o ORFX somente em:

* Sistemas próprios
* Laboratórios
* Ambientes internos autorizados
* Ativos para os quais exista permissão explícita

A autorização é responsabilidade do operador.

> A capacidade técnica de enviar uma requisição não implica autorização para fazê-lo.

---

## Licença

Este projeto é distribuído sob a licença **MIT**.

Consulte o arquivo [LICENSE](LICENSE) para os termos completos.

---

## Documentação adicional

Para informações específicas do projeto:

```text
ETHICS.md
SECURITY.md
CHANGELOG.md
```
