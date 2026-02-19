# SIEM (OpenSearch) Entorno de Laboratorio

Este proyecto despliega una arquitectura SIEM basada en OpenSearch para ingestar threat intelligence, correlacionar inicios de sesión y visualizar alertas. Incluye OpenSearch, OpenSearch Dashboards, Logstash y un demo-runner en Python.

## Requisitos
- Docker
- Docker Compose

## Contenedores y Función
- opensearch: motor de búsqueda y almacenamiento de datos SIEM
- dashboards: interfaz web para explorar índices y crear visualizaciones
- logstash: ingesta de datos por TCP, archivos locales y threatfeed (Spamhaus DROP)
- demo-runner: correlación de IPs contra threatfeed y escritura de alertas

## Puertos
- OpenSearch: http://localhost:9201
- Dashboards: http://localhost:5602
- Logstash TCP input: host 5001 → contenedor 5000
- Logstash monitoring: http://localhost:9600

## Estructura de Carpetas
- docker-compose.yml: orquestación de servicios
- logstash/pipeline/logstash.conf: pipeline de Logstash
- datasets/: datasets locales (JSON, un objeto por línea)
- siem-demo/: demo en Python

## Inicio rápido
```bash
docker compose up -d
```

Verificación rápida:
```bash
curl -s http://localhost:9201 | head -n 5
```

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

Ejemplo de recarga de archivos locales:
```bash
docker compose up -d --force-recreate logstash
```

## Demo de correlación y alertas
El demo-runner:
- Lee threatfeed desde `threatfeed-*`
- Lee login logs desde `login-logs`
- Compara IPs contra rangos CIDR del threatfeed
- Escribe alertas en `alerts`

Para ejecutarlo manualmente:
```bash
docker compose up -d --force-recreate demo-runner
```

Variables principales:
- OPENSEARCH_URL
- OPENSEARCH_THREAT_INDEX
- OPENSEARCH_LOGIN_INDEX
- OPENSEARCH_ALERT_INDEX

## Ver resultados en Dashboards
1. Abre http://localhost:5602
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
