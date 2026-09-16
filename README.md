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
