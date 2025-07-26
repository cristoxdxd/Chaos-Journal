# [PWN or DIE - 2025](https://revers3everything.com/pwn-or-die-event/)

## Cuando el paquete ataca `instld`

> "El caos es el orden en estado puro."
> — Santino Suntaxi, Malware

### Automatización de instalaciones sin requirements.txt

`instld` es una herramienta que permite instalar e importar paquetes de Python en tiempo real, sin necesidad de un archivo `requirements.txt`. Es especialmente útil en entornos donde se requiere una gestión rápida y dinámica de dependencias.

#### ¿Qué tan lejos puede llegar esta librería?

- Simulación de una cadena de suministro maliciosa.
- Infraestructura desplegada: PyPI privado con paquete malicioso.

> "Lo peligroso no es el código que ves, sino el que no ves."

#### Ejemplo de ataque

- El paquete malicioso se envía a un servidor externo (Yandex).
- Al ejecutar el código, se instala automáticamente el paquete malicioso.
- El código incluye un trigger basado en la curiosidad del usuario:

  - Si el usuario responde "sí", se ejecuta el código malicioso.
  - Si responde "no", se instala otro paquete.

- El paquete malicioso recopila información del sistema (por ejemplo, contenido de `/etc/passwd`) y la envía al servidor.

La automatización y flexibilidad de herramientas como `instld` pueden facilitar ataques de cadena de suministro si no se gestionan adecuadamente las fuentes y la seguridad de los paquetes.

## Manipulación de LLMs mediante Prompt Injection con caracteres ocultos

> "La mente es un laberinto, y los prompts son las llaves."
> — Kenji Morales, RedTeam, AI Hacking

Los LLMs (Modelos de Lenguaje Grande) son sistemas de inteligencia artificial diseñados para comprender y generar texto en lenguaje natural, facilitando tareas como asistencia, redacción y análisis de información.

#### ¿Qué es un Prompt Injection?

El Prompt Injection es una técnica de ataque que consiste en manipular el texto de entrada (prompt) para alterar el comportamiento del modelo de IA. Esto puede lograrse mediante la inserción de caracteres ocultos o comandos especiales, que el modelo interpreta de manera inesperada, permitiendo al atacante influir en las respuestas generadas.

En un caso reportado por Hunter en HackerOne, se identificó una vulnerabilidad relacionada con el uso de `Tag Characters`. Aunque la vulnerabilidad permitía modificar el comportamiento del modelo, HackerOne redujo la severidad al considerar que la integridad podía ser verificada por un humano. Para mitigar el riesgo, se reconfiguró el LLM, evitando que interpretara los caracteres ocultos como comandos, lo que neutralizó la vulnerabilidad.

## ¿Cómo asegurar criptográficamente los archives de Wazuh?

> "La seguridad no es un producto, es un proceso."
> — Nelson Cacuango, BlueTeam



## Plug & Pwn: Cómo un USB puede Pwnearte sin que lo notes

> — Jorge Sánchez, RedTeam, Social Engineering

## Infraestructura Bajo Ataque: Descubriendo las Vulnerabilidades de Switches y Routers

> — Alex Caizapanta, Pentesting

## El arte de romper el WAF sin romper el internet

> — Danny Ramirez, Research CVE

## De Intruso a HackerOne Privado: Compras gratis infinitas

> — Anthony López, Bug Bounty

## When Your Mind Becomes the Exploit: No Code, No Tools

> — Xavier Riofrío, RedTeam, Social Engineering

## Content Security Policy ¿El fin de XSS?

> — Santos Gallegos, Web Hacking

## Tu Suministro, Su Acceso: Rompiendo la Cadena de suministro

> — David Cortez, Malware

## Offensive Copilot: Agentic IA para Operaciones Ofensivas Avanzadas

> — Jorge Moya, RedTeam

## The light part of the dark web

> — Christian Oña, DarkWeb

## De 0day a CVE: Vender el Exploit o Reportar a MITRE

> — Nakleh Said Zeidan Silva, RedTeam, Research CVE

## IDORs Everywhere: The Mother of Data Breaches

> — Galoget Latorre, Web Hacking

## No eres lo suficientemente paranoicx

> — Ola Bini, Privacy and Anonimity

## Escaneo Silencioso, Daño Ruidoso

> — Omar Salazar, Hacking Metro de Quito
