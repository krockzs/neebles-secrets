# N.E.E.B.L.E.S. Secrets

`neebles-secrets` será un componente vital del ecosistema N.E.E.B.L.E.S.

No será un módulo normal instalable o removible por el usuario. Pertenece a la categoría de componentes estructurales que Boss considera parte de la base del ecosistema, del mismo modo conceptual que otros componentes vitales como OS o Testing.

## Propósito

Centralizar en un único componente capacidades relacionadas con generación segura, credenciales, secretos y operaciones criptográficas reutilizables por todo el ecosistema.

La meta es evitar que cada módulo tenga que implementar por separado:

- generación de strings alfanuméricos aleatorios;
- generación de tokens;
- UUID e identificadores;
- bytes aleatorios criptográficamente seguros;
- salts;
- peppers;
- claves;
- hashing de contraseñas;
- verificación de hashes;
- cifrado y descifrado;
- codificaciones;
- secretos recuperables;
- futuras primitivas criptográficas.

## Principio arquitectónico

N.E.E.B.L.E.S. mantiene el principio:

> Boss gobierna; el módulo declara; el componente ejecuta.

Para `neebles-secrets`:

```text
módulo
  ↓
solicitud declarativa
  ↓
Boss
  ↓
neebles-secrets
  ↓
capacidad solicitada
  ↓
resultado
```

Los módulos consumidores no necesitan conocer la implementación criptográfica concreta ni repetir lógica sensible.

## Componente vital

`neebles-secrets` no será un módulo normal.

Será uno de los componentes vitales del ecosistema: piezas estructurales que pueden tener su propio repositorio, versión, releases y evolución, pero cuya presencia forma parte de la base que Boss y Stage0 pueden garantizar.

Conceptualmente:

```text
NEEBLES
├─ Boss
│  └─ gobierna
│
├─ Vital Components
│  ├─ os
│  ├─ testing
│  └─ secrets
│
└─ Normal Modules
   └─ ...
```

Un componente vital no debería ser removible por el usuario mediante el lifecycle normal de módulos.

## Fractalidad y contratos basados en String

La interfaz deberá conservar la filosofía fractal de N.E.E.B.L.E.S. y utilizar contratos simples y extensibles basados principalmente en `String`.

Ejemplo conceptual:

```text
operation = "random.alphanumeric"
length = "32"
```

Otro ejemplo:

```text
operation = "password.hash"
algorithm = "argon2id"
```

La nomenclatura definitiva se definirá al implementar el proyecto.

## Diccionario declarativo de capacidades

`neebles-secrets` deberá disponer de un JSON versionado dentro de su propio repositorio que describa las capacidades disponibles.

La idea es que el componente pueda evolucionar sin obligar a modificar cada módulo consumidor cuando aparezca una nueva tecnología.

Conceptualmente:

```text
capacidad solicitada
        ↓
diccionario JSON
        ↓
provider / primitive permitida
        ↓
resultado
```

Ejemplo conceptual, no contractual:

```json
{
  "hash.argon2id": {
    "family": "password_hash",
    "provider": "native"
  },
  "hash.yescrypt": {
    "family": "password_hash",
    "provider": "native"
  },
  "random.alphanumeric": {
    "family": "random"
  },
  "random.hex": {
    "family": "random"
  }
}
```

El JSON será declarativo.

No deberá convertirse en un mecanismo de ejecución arbitraria de comandos. `neebles-secrets` seguirá controlando qué primitivas, providers y operaciones están autorizados.

## Familias previstas

El diseño podrá contemplar familias como:

```text
random.*
token.*
password.*
hash.*
verify.*
key.*
encrypt.*
decrypt.*
encode.*
```

Estas familias son conceptuales y no constituyen todavía un contrato definitivo.

## Generación aleatoria

Una responsabilidad importante será proporcionar generación reutilizable para cualquier módulo.

Ejemplos:

- alfanuméricos;
- hexadecimal;
- Base64 / Base64URL;
- bytes criptográficamente seguros;
- UUID u otros identificadores;
- salts;
- tokens;
- secretos;
- claves.

Ejemplo conceptual:

```json
{
  "operation": "random.alphanumeric",
  "length": "48"
}
```

El módulo recibe el resultado y no necesita implementar su propio RNG ni sus propias políticas.

## Contraseñas

Las contraseñas deberán tratarse mediante hashing irreversible, no mediante cifrado reversible.

Flujo conceptual:

```text
password
+ salt aleatorio
+ material adicional opcional
↓
algoritmo de password hashing
↓
String resultante
```

Tecnologías potenciales:

- Argon2id;
- yescrypt;
- futuras tecnologías consideradas adecuadas.

El algoritmo y sus parámetros deberán poder evolucionar por política.

## Pepper

El diseño podrá incorporar material externo como pepper.

Conceptualmente:

```text
password
+ salt
+ pepper
↓
hash
```

El pepper no debe almacenarse junto al hash persistido.

Su custodia y obtención deberán permanecer separadas de la representación almacenada.

## Material criptográfico

La arquitectura deberá poder abstraer el origen del material requerido por cada operación.

Conceptualmente:

```text
material
├─ none
├─ pepper
├─ symmetric_key
├─ public_key
├─ private_key
└─ provider futuro
```

La operación no debería necesitar conocer dónde está almacenado físicamente dicho material.

## Secrets recuperables

No todos los valores sensibles pueden resolverse mediante hashing.

Algunos secretos deberán recuperarse posteriormente para ser utilizados, por ejemplo:

- API tokens;
- credenciales hacia sistemas externos;
- claves privadas;
- secretos de integración.

Estos casos requieren cifrado reversible y deben permanecer conceptualmente separados del password hashing.

## Integración futura con Settings

Una de las principales motivaciones del proyecto es permitir que un campo `String` de Settings pueda declararse como sensible.

Ejemplo conceptual:

```text
type = string
protection = password
```

Boss delegaría la protección a `neebles-secrets` antes de persistir el valor.

El texto plano no debería llegar a `local_settings_<module>.json`.

El valor persistido seguirá siendo un `String`, preservando el contrato general de Settings.

## Verificación centralizada

En algunos escenarios el módulo consumidor ni siquiera debería necesitar recibir el hash almacenado.

Podría solicitar una verificación centralizada:

```text
módulo
→ Boss
→ neebles-secrets
→ verifica candidato
→ true / false
```

Esto permite mantener la autoridad sobre credenciales en la capa estructural del ecosistema.

## Almacenamiento local de secretos de usuario: KeePassXC

Para usuarios de N.E.E.B.L.E.S. OS, `neebles-secrets` utilizará **KeePassXC** como almacén local de secretos persistentes cuando un módulo requiera este componente.

KeePassXC es software libre y multiplataforma, disponible en Linux y Windows, y utiliza bases de datos `.kdbx`.

La intención es no convertir N.E.E.B.L.E.S. en otro gestor de contraseñas ni reinventar una bóveda propia. `neebles-secrets` gobernará el contrato y la generación del material, mientras KeePassXC actuará como mecanismo de custodia local.

El programa no tiene por qué formar parte permanente de una instalación limpia de N.E.E.B.L.E.S. OS. Si un módulo instalado declara dependencia de `neebles-secrets`, el sistema podrá instalar KeePassXC como dependencia y avisar al usuario de que ese módulo utilizará un almacén local de secretos.

Las bases y archivos necesarios deberán vivir **fuera de las carpetas internas del ecosistema N.E.E.B.L.E.S.**. No deberán guardarse dentro de `/opt/neebles` ni confundirse con repositorios o settings internos de los módulos.

Regla fundamental:

```text
¿existe el material de claves?
├─ sí  → preservar; nunca sobrescribir automáticamente
└─ no  → generar y registrar
```

Esto permite que una reinstalación, reparación o actualización no regenere accidentalmente una identidad criptográfica existente.

## Dos caminos de integración con KeePassXC

Actualmente se contemplan dos caminos técnicos de integración. La elección definitiva se realizará durante la implementación.

### Camino 1 — `keepassxc-cli`

KeePassXC ofrece `keepassxc-cli`, que permite automatizar operaciones sobre una base `.kdbx` desde procesos controlados.

Conceptualmente:

```text
módulo
↓
neebles-secrets
↓
keepassxc-cli
↓
base .kdbx externa al ecosistema NEEBLES
```

Este camino permite mantener la integración explícita, automatizable y acotada a una base administrada por `neebles-secrets`.

### Camino 2 — Secret Service / D-Bus de KeePassXC

KeePassXC también puede integrarse mediante interfaces de escritorio basadas en D-Bus / Secret Service.

Conceptualmente:

```text
módulo
↓
neebles-secrets
↓
D-Bus / Secret Service
↓
KeePassXC
```

Este camino puede resultar útil cuando convenga integrarse con mecanismos estándar de sesión de usuario. Si se utiliza, el usuario deberá ser informado porque implica una integración más directa con el entorno de escritorio.

Ninguno de los módulos consumidores deberá acoplarse directamente a KeePassXC. Ambos caminos deben permanecer detrás del contrato de `neebles-secrets`.

## Separación entre desktop y backend

El problema de custodia de secretos para un usuario de N.E.E.B.L.E.S. OS no es necesariamente el mismo que el de un backend o servidor.

En desktop se priorizará KeePassXC como almacén persistente de usuario.

En backend, `neebles-secrets` podrá admitir providers distintos, por ejemplo:

```text
.env
systemd credentials
variables de entorno
vaults externos
providers futuros
```

Los módulos no deberían necesitar conocer qué provider físico está detrás.

## Material efímero por transacción

`neebles-secrets` deberá distinguir entre material persistente y material efímero.

Conceptualmente:

```text
persistent material
└─ identidad / claves de largo plazo

ephemeral material
└─ nuevo material por transacción
   ↓
   usar
   ↓
   descartar
```

Cuando una operación requiera cifrado reversible, la intención es poder generar material fresco por transacción para evitar reutilización innecesaria de claves o nonces y reducir correlación entre operaciones.

Los algoritmos y construcciones concretas deberán usar primitivas criptográficas estándar y auditadas; N.E.E.B.L.E.S. abstraerá el contrato, no inventará nuevos algoritmos criptográficos.

## Respaldo y recuperación

Un secreto persistente útil debe poder sobrevivir a una reinstalación del sistema.

Los módulos que dependan de `neebles-secrets` deberán poder informar al usuario qué material externo necesita conservar para recuperar su identidad o sus datos después de formatear.

La intención es que `neebles restore` pueda integrar en el futuro el material externo administrado por `neebles-secrets` dentro de sus respaldos, sin que `neebles-installer` necesite conocer los detalles internos de KeePassXC.

Conceptualmente:

```text
neebles restore
↓
pregunta a neebles-secrets
↓
¿qué material externo pertenece a este módulo?
↓
respalda / restaura
```

`neebles-secrets` deberá conservar la autoridad sobre las rutas, identificadores y artefactos necesarios.

## Respaldo remoto opcional con Google Drive

También se contempla conectar `neebles-secrets` con Google Drive para ofrecer respaldo automático del material crítico y reducir el riesgo de pérdida por olvido del usuario.

El respaldo remoto no deberá subir una clave sensible en texto plano.

Conceptualmente:

```text
key local
↓
protección / wrapping de recuperación
↓
artefacto cifrado de backup
↓
Google Drive
```

El material utilizado para recuperar el backup no debe depender únicamente de la misma clave que está siendo respaldada, para evitar una dependencia circular.

Google Drive deberá considerarse un provider de respaldo, no la autoridad criptográfica.

La arquitectura deberá permitir en el futuro otros providers de backup sin modificar los módulos consumidores:

```text
google_drive
local_export
nextcloud
s3
provider futuro
```

## Evolución tecnológica

Uno de los objetivos fundamentales es evitar acoplar N.E.E.B.L.E.S. a un algoritmo específico.

Si aparece una nueva tecnología:

```text
release anterior
→ capacidades actuales

release nuevo
→ nueva capability
→ nuevo provider
→ nueva política
```

Los módulos consumidores no deberían necesitar cambios mientras el contrato lógico permanezca estable.

La identidad de una capacidad puede mantenerse mientras su implementación evoluciona detrás del contrato.

## Versionado

`neebles-secrets` tendrá su propio:

- repositorio;
- versionado;
- releases;
- diccionario de capacidades;
- contrato de compatibilidad.

Boss deberá conocer únicamente el contrato necesario para gobernarlo.

## Relación con Stage0

Al tratarse de un componente vital, Stage0 podrá verificar en el futuro su presencia e integridad.

Conceptualmente:

```text
Stage0
↓
verifica neebles-secrets
↓
versión
↓
integridad
↓
dependencias
↓
repara si corresponde
↓
ecosistema continúa
```

La política exacta se definirá cuando el componente sea implementado.

## Estado

Proyecto conceptual.

No implementar todavía.

La arquitectura definitiva, contratos, schema JSON, IPC, política de claves, almacenamiento de material criptográfico, algoritmos iniciales y relación exacta con Boss y Stage0 se definirán cuando este repositorio sea retomado.
