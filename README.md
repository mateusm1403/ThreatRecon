# ThreatRecon

ThreatRecon é uma ferramenta plug and play desenvolvida em Python para Reconhecimento Passivo, OSINT e mapeamento de superfície de ataque externa.

A ideia do projeto surgiu da necessidade de visualizar, consolidar e acompanhar informações publicamente expostas por organizações na internet de forma simples, organizada e automatizada.

A ferramenta recebe um domínio alvo, realiza coleta passiva de dados públicos, correlaciona os achados, armazena o histórico em SQLite e gera relatórios profissionais em HTML, CSV e JSON.

## ThreatRecon foi projetado para ser:

simples de executar
fácil de expandir
útil em cenários reais
seguro e ético
Por que o ThreatRecon existe?

## Organizações frequentemente expõem informações sem perceber:

subdomínios esquecidos
emails públicos
metadados sensíveis
tecnologias expostas
possíveis credenciais vazadas
indicadores de exposição externa

ThreatRecon ajuda a visualizar essa superfície de ataque utilizando apenas técnicas passivas e fontes públicas.

## O objetivo não é exploração ofensiva, mas sim:

visibilidade
inteligência
monitoramento
redução de exposição
Funcionalidades
Reconhecimento e Coleta
Crawling leve de páginas públicas
Descoberta passiva de subdomínios
Resolução DNS de hosts encontrados
Coleta de metadados públicos em PDFs
Extração de emails
Identificação básica de tecnologias
Inteligência e Correlação
Consolidação de dados com pandas
Correlation engine para organização dos achados
Detection de possíveis chaves/API tokens expostos
Exposure Score de 0 a 100
Comparação entre scans anteriores
Relatórios
Relatório HTML profissional
Exportação CSV
Exportação JSON
Histórico persistente em SQLite
Arquitetura
Estrutura modular e escalável
Async crawling com httpx + asyncio
CLI amigável com Typer
Logging estruturado com loguru
Configuração via .env
Segurança e Ética

ThreatRecon foi desenvolvido para operar de forma estritamente passiva.

## O projeto NÃO implementa:

bruteforce
exploração de vulnerabilidades
bypass
credential attacks
intrusive probing
scanning agressivo

## A ferramenta deve ser utilizada apenas em:

ativos próprios
ambientes autorizados
pesquisas OSINT legítimas

## Estrutura do Projeto

```
ThreatRecon/
  main.py
  requirements.txt
  .env.example
  README.md
  threatrecon/
    app/
      core/
      orchestrator/
      collectors/
      extractors/
      enrichers/
      correlation/
      storage/
      reporting/
      cli/
  reports/
  tests/
Fluxo de Funcionamento
Domínio alvo
     ↓
Coleta passiva
     ↓
Extração de indicadores
     ↓
Correlação dos dados
     ↓
Cálculo do Exposure Score
     ↓
Persistência em SQLite
     ↓
Geração de relatório
```

## Instalação

1. Criar ambiente virtual
python -m venv .venv
.\.venv\Scripts\Activate.ps1
2. Instalar dependências
pip install -r requirements.txt
3. Configurar ambiente
Copy-Item .env.example .env

## Uso

### Executar scan
python main.py scan example.com
### Ver histórico
python main.py history
### Ver histórico de um domínio
python main.py history example.com --limit 5
### Executar com logs detalhados
python main.py scan example.com --verbose
### Limitar crawling
python main.py scan example.com --max-pages 5
### Desabilitar crt.sh
python main.py scan example.com --no-crtsh

## Exemplo de Saída
Exposure score: 34/100
Findings: 18

HTML report:
reports/threatrecon_example.com_20260521_153000_1.html

CSV export:
reports/threatrecon_example.com_20260521_153000_1.csv

JSON export:
reports/threatrecon_example.com_20260521_153000_1.json
Configuração

O ThreatRecon lê automaticamente o arquivo .env.

THREATRECON_MAX_PAGES=15
THREATRECON_MAX_PDFS=5
THREATRECON_TIMEOUT_SECONDS=10
THREATRECON_REQUEST_DELAY_SECONDS=0.2
THREATRECON_USER_AGENT=ThreatRecon/0.1 OSINT Scanner
THREATRECON_DATABASE_PATH=threatrecon.db
THREATRECON_REPORTS_DIR=reports
THREATRECON_ENABLE_CRTSH=true

## Conteúdo do Relatório

O relatório HTML inclui:

```
resumo executivo
exposure score
emails encontrados
subdomínios
IPs
tecnologias identificadas
possíveis vazamentos
indicadores críticos
metadados de PDFs
mudanças desde o último scan
Exemplo de Finding JSON
{
  "type": "possible_secret",
  "value": "abcd...1234",
  "source": "https://example.com/app.js",
  "severity": "critical",
  "evidence": "Pattern matched: generic_api_secret",
  "metadata": {
    "pattern": "generic_api_secret"
  }
}
```
## Desenvolvimento

Executar testes:

pytest

A arquitetura foi desenhada para facilitar expansão futura:

novos collectors
novos enrichers
novas integrações OSINT
novos mecanismos de correlação
melhorias de scoring
novos templates de relatório
Roadmap

## Planejamentos futuros:

integração com Shodan
GitHub dorks
análise Wayback Machine
ASN mapping
dashboard web
exportação PDF
monitoramento contínuo
alertas de mudança de superfície
Observações

O primeiro scan de um domínio funciona como baseline inicial.

A partir do segundo scan, o ThreatRecon compara automaticamente os novos resultados com o histórico armazenado no SQLite para identificar mudanças na superfície de ataque.
