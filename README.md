# SIEM (ELK) Entorno de Laboratorio

Este proyecto despliega ELK (Elasticsearch, Logstash y Kibana) con Docker Compose en local para recibir y visualizar logs de seguridad. Soporta dos entradas de datos: TCP en tiempo real y carga desde archivos locales.

## Requisitos
- Docker
- Docker Compose

## Servicios y Puertos
- Elasticsearch: http://localhost:9200
- Kibana: http://localhost:5601
- Logstash TCP input: host 5001 → contenedor 5000

## Estructura de Carpetas
- docker-compose.yml: orquestación de servicios ELK
- logstash/pipeline/logstash.conf: pipeline de Logstash
- datasets/: datasets locales (NDJSON, un JSON por línea)

## Pasos Realizados (registro)
1. Definición de servicios ELK con Docker Compose (ES/Kibana/Logstash).
2. Añadido input TCP en Logstash para escritura en tiempo real.
3. Añadido input de archivos en Logstash para leer NDJSON desde datasets/.
4. Habilitado JSON codec en el input de archivos para parseo directo.
5. Añadido método de importación y verificación de datos reales de Suricata.

## Despliegue e Inicio
```bash
docker compose up -d
```

Validación de servicios:
```bash
curl -s http://localhost:9200 | head -n 5
```

## Añadir Datos (Método A: TCP en tiempo real)
Adecuado para escritura temporal o importación en streaming.

```bash
printf '{"@timestamp":"2026-02-10T10:00:00Z","event":"test","source":"manual","message":"hello elk"}\n' \
| nc -w 1 localhost 5001
```

Verificación:
```bash
curl -s "http://localhost:9200/siem-*/_search?size=3" | head -n 40
```

## Añadir Datos (Método B: Importación desde archivos locales)
1. Coloca NDJSON en el directorio datasets/ (un JSON por línea).
2. Reinicia Logstash para activar la lectura de archivos:

```bash
docker compose up -d --force-recreate logstash
```

## Importar Datos Reales (muestra de alertas Suricata)
Descarga e importa 200 alertas de un dataset público (estructura real):  
Fuente: https://github.com/FrankHassanabad/suricata-sample-data

```bash
curl -L https://raw.githubusercontent.com/FrankHassanabad/suricata-sample-data/master/samples/wrccdc-2018/alerts-only.json \
| python3 -c 'import sys,json,itertools; data=json.load(sys.stdin); \
for obj in itertools.islice(data, 200): \
    sys.stdout.write(json.dumps(obj)+"\n")' \
| nc -w 2 localhost 5001
```

Verificación:
```bash
curl -s "http://localhost:9200/siem-*/_search?size=3&q=event_type:alert" | head -n 40
```

## Visualización en Kibana
1. Abre Kibana: http://localhost:5601  
2. Crea Index Pattern: `siem-*`  
3. Ejemplo de consulta KQL:  
   - `event_type : "alert"`

## Resumen del Pipeline de Logstash
- Input TCP: escucha 5000 (contenedor) para eventos JSON Lines.
- Input File: lee /data/*.json (mapeado desde datasets/).
- Output: indexa en `siem-YYYY.MM.dd`.
