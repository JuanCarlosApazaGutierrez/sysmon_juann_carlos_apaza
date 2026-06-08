# Sysmon MITRE & OWASP Analyzer

Este proyecto es una plataforma interactiva web diseñada para la ingesta, análisis y correlación de telemetría de Windows Sysmon con los marcos de trabajo de ciberseguridad MITRE ATT&CK y OWASP. Fue desarrollado como parte de la evaluación práctica del módulo.

**Programa:** Maestría en Informática Forense, Ciberseguridad y Auditoría con Aplicación de IA
**Módulo:** IV - Fundamentos de Ciberseguridad y Protección con IA (UMSA)
**Maestrante:** Juan Carlos Apaza Gutierrez

---

## 🎯 Arquitectura del Proyecto

El proyecto está dividido en dos capas principales, diseñadas para ser modulares, eficientes y fácilmente desplegables en entornos locales:

1. **Frontend (React / Next.js):**
   - Una aplicación de página única (SPA) rica e interactiva que corre en el navegador del analista.
   - Todo el **motor de análisis y parsing** se ejecuta del lado del cliente (`lib/sysmonParser.ts`). Esto garantiza que grandes archivos JSON se puedan procesar instantáneamente usando el CPU local sin necesidad de subir gigabytes a la red.
   - Proporciona un dashboard analítico, gráficos estadísticos y un gestor de alertas en tiempo real con capacidades de búsqueda y filtrado de alto rendimiento.

2. **Backend (Python / Flask / SQLite):**
   - Una API ligera y ultra-rápida.
   - Base de datos relacional sin configuración (`SQLite`) para almacenar el historial de análisis JSON y observaciones del analista de manera persistente.
   - Funciona como un sistema de almacenamiento de evidencia que el Frontend puede consultar para revisar reportes antiguos mediante la pestaña "Informes".

---

## 🚀 Funcionalidades Principales

- **Ingesta Client-Side:** Carga archivos exportados desde Sysmon en formato JSON mediante drag & drop y sin límites artificiales del servidor.
- **Correlación MITRE ATT&CK:** Enlace automático de reglas de Sysmon a tácticas y técnicas de MITRE (ej. _T1547.001 - Persistence_).
- **Mapeo de Top 10 OWASP:** Clasificación de vulnerabilidades sistémicas y vectores de ataque identificados, de acuerdo a las guías críticas de OWASP.
- **Gráficos Dinámicos:** Visualización de Top Event IDs, Distribución de Severidades (Critical, High, Medium, Low), Top Tácticas MITRE y OWASP a través de `recharts`.
- **Registro Histórico:** Posibilidad de añadir notas personalizadas de investigación y guardar todo el reporte y el payload JSON puro en la base de datos local SQLite para revisiones posteriores.

---

## ⚙️ Cómo ejecutar localmente el proyecto

El proyecto requiere que tanto el servidor Backend como la aplicación Frontend estén en ejecución.

### 1. Iniciar el Backend (Base de datos SQLite)
Abre una terminal y dirígete al directorio del backend:
```bash
cd c:\Asignacion-Sysmon\tarea-parte2\backend
```
Activa tu entorno virtual (si usas uno) y ejecuta el servidor de Flask:
```bash
python app.py
```
> El servidor iniciará en `http://localhost:5000`. Esto creará automáticamente el archivo de base de datos `sysmon_data.db` en esa carpeta la primera vez que inicie.

### 2. Iniciar el Frontend (Next.js)
Abre **otra** terminal y dirígete al directorio del frontend:
```bash
cd c:\Asignacion-Sysmon\tarea-parte2\frontend
```
Instala las dependencias (solo necesario la primera vez):
```bash
npm install
```
Levanta el servidor de desarrollo web:
```bash
npm run dev
```
> La interfaz del dashboard estará disponible en `http://localhost:3000`.

---

## 🧠 Justificación de Tecnologías

Para garantizar una experiencia de analista de ciberseguridad fluida, se eligieron las siguientes tecnologías:

- **Next.js & React:** Se seleccionó por su arquitectura basada en componentes y la capacidad de manejar flujos de estado complejos en el navegador. La reactividad de React permite que la tabla de alertas y los gráficos se filtren en tiempo real sin recargar la página.
- **Tailwind CSS:** Proveé utilidades de estilo CSS "utility-first" que permitieron crear rápidamente un diseño moderno, responsivo y un **Modo Oscuro** (Dark Mode) nativo, esencial para no agotar la vista de los analistas durante investigaciones prolongadas.
- **Recharts:** Librería de visualización de datos construida sobre React y D3. Elegida por su facilidad para generar gráficos interactivos, SVG limpios y tooltips dinámicos con poco esfuerzo de configuración.
- **Python / Flask / SQLite:** El backend se diseñó intencionadamente minimalista. Flask permite levantar endpoints REST en pocas líneas, y SQLite exime al usuario de tener que instalar motores de bases de datos pesados como MySQL o PostgreSQL para almacenar el registro de actividad forense.
