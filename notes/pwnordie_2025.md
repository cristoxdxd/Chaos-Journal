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

Una solución efectiva para proteger la integridad de los archivos en Wazuh es implementar un sistema de validación automatizada que detecte cualquier modificación no autorizada. Si un atacante altera los archivos, estos se vuelven inválidos, ya que se ha comprometido su integridad. Para fortalecer este proceso, se puede utilizar el mecanismo de timestamping definido en el RFC 3161, que permite sellar criptográficamente los archivos con una marca de tiempo confiable. Así, cualquier intento de manipulación posterior será detectado, garantizando que los archivos no hayan sido vulnerados desde su creación y facilitando la verificación automatizada de su integridad.

## Plug & Pwn: Cómo un USB puede Pwnearte sin que lo notes

> — Jorge Sánchez, RedTeam, Social Engineering

La ingeniería social es una técnica utilizada para manipular a las personas y obtener información confidencial. Entre sus métodos más comunes se encuentran el phishing, el pretexting y el baiting. El proceso inicia con una fase de reconocimiento y preparación, donde se emplean herramientas OSINT para la recopilación de datos y la creación de perfiles de las víctimas. Posteriormente, se procede a la suplantación y ejecución del ataque, que puede culminar en la filtración de datos, como ocurrió en Ecuador en 2021. Un caso práctico relevante es el uso de `Mimikatz` para extraer credenciales. Para mitigar estos riesgos, es fundamental capacitar al personal en la identificación y prevención de ataques de ingeniería social.

## Infraestructura Bajo Ataque: Descubriendo las Vulnerabilidades de Switches y Routers

> — Alex Caizapanta, Pentesting

Los switches y routers suelen ser los grandes olvidados en las auditorías de seguridad, a pesar de que una mala configuración o el uso de valores por defecto pueden abrir la puerta a vulnerabilidades críticas. Ejemplos como el ataque de buffer overflow en switches, la explotación de servicios como SNMP y TFTP (usando herramientas como `snmp-check` o `cisco7crack`), y la presencia de botnets DDoS en el core de la red demuestran el riesgo real. Cloudflare reportó el bloqueo de 20,5 millones de ataques DDoS, incluyendo inundaciones SYN, DNS y UDP, así como variantes de MIRAI dirigidas a dispositivos IoT. La protección efectiva requiere revisar y endurecer la configuración de estos dispositivos, eliminando credenciales por defecto y deshabilitando servicios innecesarios para evitar que se conviertan en vectores de ataque.

## El arte de romper el WAF sin romper el internet

> — Danny Ramirez, Research CVE

Romper el WAF sin romper la red implica comprender a fondo el funcionamiento del firewall y su lógica de protección. El proceso suele incluir:

- Reconocimiento de la superficie de ataque y análisis de los vectores disponibles.
- Uso de enfoques manuales y combinados para identificar debilidades, como pruebas de caja negra y revisión de código.
- Consideración de la presencia de un proveedor (vendor) y posibles bypasses específicos, como técnicas tipo "shadowclone".

El objetivo es evadir el WAF sin afectar la integridad de la red, priorizando la confidencialidad y minimizando el impacto. Entender el comportamiento del WAF es clave para encontrar rutas alternativas y explotar vulnerabilidades sin interrumpir el servicio.

## De Intruso a HackerOne Privado: Compras gratis infinitas

> "No se trata de romper sistemas, sino de entenderlos para mejorarlos."
> — Anthony López, Bug Bounty

### aka sk8ware

El proceso implica la generación de tarjetas falsas utilizando BINs, seguido de la verificación para identificar cuáles superan los controles de seguridad y permiten el bypass. Se aprovecha una vulnerabilidad en la lógica de negocio, detectando un error crítico que posibilita la explotación del sistema. Luego, se desarrolla un repetidor que valida y agrega automáticamente las tarjetas aceptadas, permitiendo realizar compras ilimitadas sin necesidad de fondos reales.

## When Your Mind Becomes the Exploit: No Code, No Tools

> "Romper sistemas empieza por romper paradigmas."
> — Xavier Riofrío, RedTeam, Social Engineering

¿Es posible vulnerar sistemas sin escribir una sola línea de código, sin escáneres ni herramientas automáticas?

- **Evasión de bloqueos:** Analizando flujos de autenticación y detectando inconsistencias en la lógica de acceso, se logró eludir restricciones sin modificar el código ni usar herramientas externas.
- **Escalada de privilegios biométricos:** Observando el comportamiento de sistemas biométricos y aprovechando errores en la validación, fue posible acceder a niveles superiores de privilegio.
- **Bypass de límites de seguridad:** Mediante el análisis de reglas y políticas, se identificaron lagunas que permitieron superar controles sin interacción técnica directa.
- **Explotación de race conditions:** Detectando condiciones de carrera en procesos manuales, se manipuló el orden de operaciones para obtener resultados no previstos por los desarrolladores.

Estos casos demuestran que pensar como atacante —cuestionando lo obvio, analizando el entorno y buscando patrones anómalos— puede ser tan poderoso como cualquier herramienta digital. La invitación es a romper esquemas mentales, entender la lógica detrás de los sistemas y descubrir vulnerabilidades solo con la mente, recordando que la seguridad no es solo cuestión de tecnología, sino de perspectiva.

## Content Security Policy ¿El fin de XSS?

> "Una política mal definida puede convertir una defensa en una vulnerabilidad."
> — Santos Gallegos, Web Hacking

Aunque CSP es una herramienta poderosa para mitigar ataques XSS, una configuración incorrecta puede abrir la puerta a la filtración de datos sensibles. Por ejemplo, si la política permite fuentes externas no confiables en `script-src` o `img-src`, un atacante puede inyectar código que envíe información confidencial (como cookies, tokens o datos de formularios) a servidores bajo su control. Además, el uso excesivo de directivas como `unsafe-inline` o la omisión de restricciones en `connect-src` puede facilitar la exfiltración mediante peticiones AJAX o WebSockets.

Para evitar estos riesgos, es fundamental definir una política CSP estricta, limitando los orígenes permitidos y evitando el uso de comodines. La revisión periódica de la configuración y la monitorización de violaciones de CSP ayudan a detectar intentos de explotación y proteger la integridad de los datos.

## Tu Suministro, Su Acceso: Rompiendo la Cadena de suministro

> "La cadena de suministro es tan fuerte como su eslabón más débil."
> — David Cortez, Malware

Vibe coding representa el concepto de Vulnerability as a Service (VaaS), donde la explotación de vulnerabilidades se convierte en un modelo de negocio accesible incluso para quienes no tienen experiencia en programación. Un ejemplo destacado es el caso de un joven que, utilizando herramientas como Cursor, logró crear y monetizar una aplicación sin conocimientos técnicos profundos. Sin embargo, al priorizar la funcionalidad sobre la seguridad, dejó su plataforma expuesta a ataques.

Los atacantes aprovechan flujos como el Revival Hijack Attack, donde se infiltra código malicioso en aplicaciones mediante dependencias comprometidas o paquetes abandonados que son retomados por actores maliciosos. Este tipo de ataque puede pasar desapercibido si no se auditan correctamente las fuentes y actualizaciones de los paquetes utilizados.

Otra técnica común es el typosquatting, que consiste en publicar paquetes con nombres similares a los legítimos, aprovechando errores tipográficos de los desarrolladores al instalar dependencias. Al instalar accidentalmente el paquete malicioso, el atacante puede ejecutar código arbitrario, comprometiendo la seguridad de la aplicación y sus usuarios.

La combinación de automatización, falta de revisión de dependencias y desconocimiento de buenas prácticas de seguridad puede convertir cualquier proyecto en un objetivo fácil para la explotación, evidenciando la importancia de integrar controles de seguridad desde el inicio del desarrollo.

## Offensive Copilot: Agentic IA para Operaciones Ofensivas Avanzadas

> "La potenciación de la IA es el futuro del hacking."
> — Jorge Moya, RedTeam

La inteligencia artificial está revolucionando el desarrollo de herramientas ofensivas, permitiendo a pentesters y hackers crear exploits personalizados de manera rápida y eficiente, incluso sin experiencia avanzada en programación. Gracias a modelos agentic y la integración con APIs, la IA puede analizar entornos, identificar vulnerabilidades y ejecutar acciones automatizadas junto a programas locales, facilitando la interacción dinámica y el aprendizaje en tiempo real.

Este enfoque reduce la barrera técnica y acelera el ciclo de desarrollo ofensivo, desde la concepción de la idea hasta la ejecución y revisión de resultados. La IA puede sugerir vectores de ataque, generar código adaptado al contexto, automatizar pruebas y documentar hallazgos, optimizando el proceso y permitiendo iteraciones rápidas.

Estrategias clave para aprovechar la IA en operaciones ofensivas:

- **Idea:** Definir el objetivo y el alcance del ataque.
- **Plan:** Diseñar la estrategia y seleccionar las herramientas adecuadas.
- **Plan + test:** Generar y validar código o payloads mediante simulaciones automatizadas.
- **Ejecución:** Desplegar los ataques y recopilar resultados en tiempo real.
- **Revisión:** Analizar el impacto, ajustar tácticas y documentar hallazgos para futuras mejoras.

La combinación de IA y automatización está transformando el hacking ofensivo, potenciando la creatividad y la eficiencia de los equipos de seguridad.

## The light part of the dark web

> — Christian Oña, DarkWeb

Anatomía de una Tarjeta de Crédito:

- **BIN (Bank Identification Number):** Identifica el banco emisor.
- **PAN (Primary Account Number):** Número de la tarjeta.
- **CVV (Card Verification Value):** Código de seguridad.
- **Fecha de Expiración:** Indica la validez de la tarjeta.
- **Nombre del Titular:** Asociado a la tarjeta.

Las entidades bancarias utilizan plantillas para generar números de tarjetas válidas, lo que permite a los atacantes crear tarjetas falsas. Estas tarjetas pueden ser utilizadas para realizar compras en línea o en puntos de venta, facilitando el fraude.

## De 0day a CVE: Vender el Exploit o Reportar a MITRE

> "La ética en la ciberseguridad es tan importante como la técnica."
> — Nakleh Said Zeidan Silva, RedTeam, Research CVE

Descubrir, explotar y reportar tu primer CVE implica un proceso técnico y ético que va más allá de la simple identificación de una vulnerabilidad. Basado en el caso real de una vulnerabilidad de ejecución remota de código (RCE) —CVE-2025-48868— en un software HRM open source, el recorrido incluye:

- **Auditoría y análisis:** Se inicia con la revisión del código fuente y la identificación de posibles vectores de ataque, empleando técnicas manuales y herramientas automatizadas para detectar fallos de seguridad.
- **Demostración práctica:** Una vez localizada la vulnerabilidad, se desarrolla un exploit funcional que permite validar el impacto real, documentando el proceso y los resultados obtenidos.
- **Dilema ético:** Surge la decisión entre monetizar el hallazgo —vendiendo el exploit en mercados privados— o reportarlo responsablemente a MITRE y al desarrollador, contribuyendo a la mejora de la seguridad global.
- **Divulgación y seguimiento:** El reporte responsable implica colaborar en la corrección del fallo, participar en el proceso de asignación del CVE y compartir el conocimiento adquirido con la comunidad, fomentando buenas prácticas y la cultura de seguridad.

Este proceso no solo requiere habilidades técnicas, sino también criterio ético y compromiso con la protección de los usuarios y la infraestructura digital.

## IDORs Everywhere: The Mother of Data Breaches

> "Los IDORs son la madre de todas las brechas de datos."
> — Galoget Latorre, Web Hacking

Los IDORs (Insecure Direct Object References) son una de las vulnerabilidades más comunes y peligrosas en aplicaciones web, permitiendo a los atacantes acceder a datos sensibles sin autorización. Estas vulnerabilidades surgen cuando una aplicación expone referencias directas a objetos internos, como archivos, registros o recursos, sin implementar controles adecuados de acceso.

Los desarrolladores a menudo piensan en el escenario ideal, donde los usuarios solo acceden a sus propios datos. Sin embargo, al no validar correctamente las solicitudes, un atacante puede manipular los parámetros de la URL o del formulario para acceder a información de otros usuarios, lo que puede resultar en filtraciones masivas de datos.

Los controles de seguridad tradicionales suelen pasar por alto los IDORs, especialmente en arquitecturas modernas basadas en microservicios y APIs. Además, la validación de acceso suele delegarse al frontend o a capas externas, dejando expuestos los recursos internos si no se verifica cada solicitud en el backend. La falta de revisiones exhaustivas y la confianza excesiva en mecanismos automáticos permiten que los IDORs persistan y sean explotados fácilmente, convirtiéndose en la madre de las brechas de datos.

## No eres lo suficientemente paranoicx

> "La privacidad es un derecho, no un lujo."
> — Ola Bini, Privacy and Anonimity

La paranoia en ciberseguridad no es solo una actitud, sino una necesidad ante el avance de la tecnología y las capacidades de espionaje. Lo que hoy parece caro y exclusivo, mañana será accesible para cualquiera. El Internet de las Cosas (IoT) ha multiplicado los vectores de ataque: en Ecuador, por ejemplo, sabemos que los autos pueden ser hackeados gracias a investigaciones como las de Danilo, y casos internacionales como el de Michael Hastings han demostrado los riesgos reales.

Edward Snowden reveló los abusos sistemáticos de la NSA, exponiendo programas como Paltalk, Tempora ("Nothing is beyond our reach") y Bullrun/Edgehill, donde se modificaron algoritmos de cifrado para debilitarlos intencionalmente. El catálogo ANT/NSA 2013 mostró herramientas de espionaje como Candygram (40K USD), Cottonmouth-I (1K USD), DropoutJeep, Firewalk, Godsurge y Howlermonkey, capaces de escuchar sin transmitir señales detectables. Incluso dispositivos cotidianos como el O.MG cable pueden ser utilizados para comprometer sistemas.

La protección contra adversarios sofisticados requiere más que respaldos convencionales. El caso de Fabian Hurtado en Ecuador evidencia que almacenar copias de seguridad en un solo lugar, incluso en el extranjero, no es suficiente. Si alguien accede a información sensible, puede causar daños significativos. Para compartir secretos de forma segura, se recomienda el uso de esquemas como Shamir Secret Sharing junto con servicios onion de Tor, aumentando la privacidad y la resiliencia ante ataques.

La seguridad física de laptops y dispositivos es fundamental: revisar el firmware, bloquear periféricos, deshabilitar cámaras y micrófonos, y emplear cifrado robusto son prácticas esenciales. El hardening de dispositivos debe ser una prioridad para minimizar la superficie de ataque.

No hay que olvidar amenazas como Tempest, que aprovechan la interferencia electromagnética para extraer información de equipos electrónicos. La paranoia bien fundamentada es el mejor aliado para proteger la privacidad y la integridad de los datos en un mundo donde el espionaje y la vigilancia avanzan sin límites.

Los dispositivos móviles cuentan con identificadores únicos que pueden ser rastreados, incluso cuando el equipo está apagado. Además, existen vectores de ataque que permiten comprometer la seguridad de un celular a través de la red móvil, sin requerir conexión a Internet, exponiendo información sensible del usuario. En la práctica, lograr un uso completamente seguro de un dispositivo móvil es imposible; siempre existen riesgos inherentes asociados a la tecnología y la infraestructura de comunicaciones.

Pegasus es un spyware desarrollado por la empresa israelí NSO Group, que permite a los atacantes acceder a información sensible en dispositivos móviles sin necesidad de interacción del usuario. Este software ha sido utilizado por gobiernos y organizaciones para espiar a periodistas, activistas y opositores políticos.

La operación triangulación es una técnica de ataque que utiliza múltiples vectores para comprometer un dispositivo.

Lockdown Mode, inhibir la cámara, micrófono, GPS y otros sensores del dispositivo móvil, es una medida de seguridad que puede ayudar a proteger la privacidad del usuario. Sin embargo, no es una solución infalible y no garantiza una protección completa contra ataques sofisticados.

Graphene OS es un sistema operativo basado en Android diseñado para mejorar la privacidad y seguridad del usuario. Ofrece características avanzadas de cifrado, control de permisos y aislamiento de aplicaciones, lo que lo convierte en una opción atractiva para quienes buscan una mayor protección en sus dispositivos móviles.

Encadenamiento de contactos, linux 0day y anonimato real son conceptos clave en la seguridad informática. El encadenamiento de contactos se refiere a la práctica de vincular múltiples dispositivos y cuentas para mejorar la seguridad y privacidad del usuario. Un 0day es una vulnerabilidad desconocida por el fabricante, que puede ser explotada por atacantes antes de que se publique un parche.

## Escaneo Silencioso, Daño Ruidoso

> "El reconocimiento es la clave para un ataque exitoso."
> — Omar Salazar, Hacking Metro de Quito

**aka Taurus Omar**  
Ex agente de contrainteligencia  
Ex asesor de seguridad de la Policía Nacional del Ecuador

El reconocimiento en operaciones de seguridad es comparable a realizar una radiografía exhaustiva del objetivo antes de ejecutar cualquier ataque. Esta fase resulta fundamental, ya que un reconocimiento efectivo puede facilitar el compromiso de sistemas críticos.

El alcance del reconocimiento abarca desde la infraestructura física hasta los sistemas de control industrial, permitiendo identificar debilidades y oportunidades en todo el entorno del objetivo.

Tipos:

- **Reconocimiento pasivo:** Implica la recopilación de información sin interactuar directamente con el objetivo, utilizando fuentes abiertas y técnicas de ingeniería social.
- **Reconocimiento activo:** Involucra la interacción directa con el objetivo, como escanear redes y sistemas para identificar vulnerabilidades y debilidades.
- **ReconBulk:** Herramienta avanzada para reconocimiento automatizado, capaz de recolectar y correlacionar información de múltiples fuentes, facilitando la identificación de activos y vulnerabilidades en grandes infraestructuras.
- **Shodan Pivoting con Property Hashes (MMHASH):** Método que permite rastrear y relacionar dispositivos en internet usando hashes de propiedades únicas, optimizando la búsqueda de sistemas similares o expuestos.
