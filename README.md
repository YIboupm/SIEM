# SIEM (Wazuh) Entorno de Laboratorio

Este proyecto despliega una arquitectura SIEM basada en Wazuh. Incluye Wazuh Manager, Wazuh Indexer, Wazuh Dashboard, Logstash y un demo-runner en Python para correlación de IPs.

## Requisitos
- Docker
- Docker Compose

## Contenedores y función
- wazuh.manager: análisis de eventos, reglas y gestión de agentes
- wazuh.indexer: almacenamiento e indexación de datos (basado en OpenSearch)
- wazuh.dashboard: interfaz web para búsqueda, visualización y app de Wazuh
- logstash: ingesta de datos por TCP, archivos locales y threatfeed (Spamhaus DROP)
- demo-runner: correlación de IPs contra threatfeed y escritura de alertas

## Puertos
- Wazuh Indexer (HTTPS): https://localhost:9201
- Wazuh Dashboard (HTTPS): https://localhost:5602
- Wazuh Manager API: https://localhost:55000
- Wazuh Agent: 1514/tcp, 1515/tcp, 514/udp
- Logstash TCP input: host 5001 → contenedor 5000
- Logstash monitoring: http://localhost:9600

## Estructura de carpetas
- docker-compose.yml: orquestación de servicios
- generate-indexer-certs.yml: generación de certificados
- config/: configuración de Wazuh Indexer y Dashboard
- logstash/pipeline/logstash.conf: pipeline de Logstash
- datasets/: datasets locales (JSON, un objeto por línea)
- siem-demo/: demo en Python

## Inicio rápido
1) Genera certificados:
```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

2) Levanta los servicios:
```bash
docker compose up -d
```

Verificación rápida:
```bash
curl -k -u admin:SecretPassword https://localhost:9201 | head -n 5
```

## Acceso a Wazuh Dashboard
- URL: https://localhost:5602
- Usuario: admin
- Contraseña: SecretPassword

## Ingesta de datos con Logstash
Logstash recibe datos de tres fuentes:
1. TCP en tiempo real en el puerto 5001
2. Archivos locales en datasets/*.json
3. Threatfeed Spamhaus DROP vía http_poller cada minuto

Ejemplo TCP:
```bash
printf '{"@timestamp":"2026-02-10T10:00:00Z","event":"test","source":"manual","message":"hello siem"}\n' \
| nc -w 1 localhost 5001
```

Recarga de archivos locales:
```bash
docker compose up -d --force-recreate logstash
```

## Demo de correlación y alertas
El demo-runner:
- Lee threatfeed desde `threatfeed-*`
- Lee login logs desde `login-logs`
- Compara IPs contra rangos CIDR del threatfeed
- Escribe alertas en `alerts`

Ejecución manual:
```bash
docker compose up -d --force-recreate demo-runner
```

Variables principales:
- OPENSEARCH_URL
- OPENSEARCH_USERNAME
- OPENSEARCH_PASSWORD
- OPENSEARCH_SSL_VERIFY
- OPENSEARCH_THREAT_INDEX
- OPENSEARCH_LOGIN_INDEX
- OPENSEARCH_ALERT_INDEX

## Ver resultados en Dashboard
1. Abre https://localhost:5602
2. Crea index patterns:
   - threatfeed-*
   - login-logs
   - alerts
3. En Discover, selecciona `alerts` y ajusta el rango de tiempo a “Last 15 minutes”

## Índices principales
- threatfeed-YYYY.MM.dd: threat intelligence de Spamhaus
- siem-YYYY.MM.dd: eventos generales recibidos por Logstash
- login-logs: logs de inicio de sesión
- alerts: alertas de correlación generadas por demo-runner
