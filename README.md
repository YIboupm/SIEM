# SIEM (Wazuh) Entorno de Laboratorio

Este proyecto despliega una arquitectura SIEM basada en Wazuh. Incluye Wazuh Manager, Wazuh Indexer, Wazuh Dashboard y un agente Wazuh para recolección de datos reales de endpoint.

## Requisitos
- Docker
- Docker Compose

## Contenedores y función
- wazuh.manager: análisis de eventos, reglas y gestión de agentes
- wazuh.indexer: almacenamiento e indexación de datos (basado en OpenSearch)
- wazuh.dashboard: interfaz web para búsqueda, visualización y app de Wazuh
- wazuh.agent: agente que recolecta datos reales y los envía al manager

## Puertos
- Wazuh Indexer (HTTPS): https://localhost:9201
- Wazuh Dashboard (HTTPS): https://localhost:5602
- Wazuh Manager API: https://localhost:55000
- Wazuh Agent: 1514/tcp, 1515/tcp, 514/udp

## Estructura de carpetas
- docker-compose.yml: orquestación de servicios
- generate-indexer-certs.yml: generación de certificados
- config/: configuración de Wazuh Indexer y Dashboard

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

## Recolección real con Wazuh Agent
El agente incluido se registra en el manager y envía eventos reales del endpoint del contenedor. En el dashboard puedes ver el agente en Agent management.

## Ver resultados en Dashboard
1. Abre https://localhost:5602
2. Entra en la app de Wazuh y revisa Agent management
3. En Discover, usa el patrón `wazuh-alerts-*` para ver alertas reales

## Índices principales
- wazuh-alerts-4.x-YYYY.MM.dd: alertas generadas por Wazuh
- wazuh-monitoring-*: métricas de Wazuh
- wazuh-statistics-*: estadísticas del manager
