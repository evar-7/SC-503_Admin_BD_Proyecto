-- =====================================================================
-- Script de Seguridad: Encriptación de Datos Sensibles y Auditorías
-- =====================================================================
-- Este script implementa medidas de seguridad para proteger datos sensibles
-- usando encriptación AES y configura auditorías para registrar actividades
-- de usuarios en la base de datos.
-- =====================================================================
-- Correr como usuario SYSTEM o con privilegios DBA
-- =====================================================================

-- =====================================================================
-- PARTE 1: TABLA PARA DATOS SENSIBLES DE CLIENTES
-- =====================================================================
-- Esta tabla almacena información sensible de clientes como datos de
-- tarjetas de crédito y correos electrónicos que serán encriptados

CREATE TABLE Datos_Sensibles_Cliente (
    ID_Datos NUMBER GENERATED ALWAYS AS IDENTITY (START WITH 1 INCREMENT BY 1) NOT NULL,
    Fk_Cliente NUMBER NOT NULL,
    Correo_Encriptado RAW(2000),
    Tarjeta_Credito_Encriptado RAW(2000),
    Fecha_Expiracion_Tarjeta DATE,
    Numero_Seguridad_Encriptado RAW(100),
    Fecha_Registro DATE DEFAULT SYSDATE,
    CONSTRAINT PK_Datos_Sensibles PRIMARY KEY (ID_Datos),
    CONSTRAINT FK_DatosSensibles_Cliente FOREIGN KEY (Fk_Cliente) REFERENCES Cliente(ID_Cliente)
) TABLESPACE VET_PROYECTO;

-- =====================================================================
-- PARTE 2: FUNCIONES DE ENCRIPTACIÓN Y DESENCRIPTACIÓN
-- =====================================================================
-- Funciones para encriptar y desencriptar datos sensibles usando AES-128
-- 
-- ADVERTENCIA DE SEGURIDAD - GESTIÓN DE CLAVES:
-- =====================================================================
-- La clave de encriptación en este script está hardcodeada SOLO para 
-- propósitos de demostración y desarrollo. 
-- 
-- EN PRODUCCIÓN SE DEBE:
-- 1. Usar Oracle Wallet para almacenar la clave de forma segura
-- 2. O usar Oracle Key Vault para gestión centralizada de claves
-- 3. O usar una función que recupere la clave de una ubicación segura
-- 4. Nunca incluir claves en scripts de código fuente
-- 
-- Ejemplo de uso con Oracle Wallet:
-- EXEC DBMS_JAVA.SET_PROPERTY('oracle.wallet.location', 
--      '(source=(method=file)(method_data=(directory=/wallet_dir)))');
-- =====================================================================

-- Función para encriptar texto usando AES-128
CREATE OR REPLACE FUNCTION encriptar_texto(p_text VARCHAR2) RETURN RAW IS
    -- Clave de encriptación de 128 bits (16 caracteres)
    -- ADVERTENCIA: Esta clave está hardcodeada solo para DEMO/DESARROLLO
    -- EN PRODUCCIÓN: Usar Oracle Wallet o Key Vault para almacenar claves
    l_key RAW(128) := UTL_I18N.STRING_TO_RAW('VET_SECRET_KEY16', 'AL32UTF8');
    l_encrypted RAW(2000);
BEGIN
    IF p_text IS NULL THEN
        RETURN NULL;
    END IF;
    
    l_encrypted := DBMS_CRYPTO.ENCRYPT(
        src => UTL_I18N.STRING_TO_RAW(p_text, 'AL32UTF8'),
        typ => DBMS_CRYPTO.ENCRYPT_AES128 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
        key => l_key
    );
    
    RETURN l_encrypted;
EXCEPTION
    WHEN OTHERS THEN
        RAISE_APPLICATION_ERROR(-20001, 'Error en encriptación: ' || SQLERRM);
END encriptar_texto;
/

-- Función para desencriptar texto usando AES-128
CREATE OR REPLACE FUNCTION desencriptar_texto(p_encrypted RAW) RETURN VARCHAR2 IS
    -- ADVERTENCIA: Esta clave está hardcodeada solo para DEMO/DESARROLLO
    -- EN PRODUCCIÓN: Usar Oracle Wallet o Key Vault para almacenar claves
    -- La clave debe coincidir exactamente con la usada en encriptar_texto
    l_key RAW(128) := UTL_I18N.STRING_TO_RAW('VET_SECRET_KEY16', 'AL32UTF8');
    l_decrypted RAW(2000);
BEGIN
    IF p_encrypted IS NULL THEN
        RETURN NULL;
    END IF;
    
    l_decrypted := DBMS_CRYPTO.DECRYPT(
        src => p_encrypted,
        typ => DBMS_CRYPTO.ENCRYPT_AES128 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5,
        key => l_key
    );
    
    RETURN UTL_I18N.RAW_TO_CHAR(l_decrypted, 'AL32UTF8');
EXCEPTION
    WHEN OTHERS THEN
        RAISE_APPLICATION_ERROR(-20002, 'Error en desencriptación: ' || SQLERRM);
END desencriptar_texto;
/

-- =====================================================================
-- PARTE 3: PROCEDIMIENTOS PARA GESTIÓN DE DATOS SENSIBLES
-- =====================================================================

-- Procedimiento para insertar datos sensibles encriptados
CREATE OR REPLACE PROCEDURE insertar_datos_sensibles(
    p_cliente_id NUMBER,
    p_correo VARCHAR2,
    p_tarjeta_credito VARCHAR2,
    p_fecha_expiracion DATE,
    p_numero_seguridad VARCHAR2
) AS
BEGIN
    INSERT INTO Datos_Sensibles_Cliente (
        Fk_Cliente,
        Correo_Encriptado,
        Tarjeta_Credito_Encriptado,
        Fecha_Expiracion_Tarjeta,
        Numero_Seguridad_Encriptado
    ) VALUES (
        p_cliente_id,
        encriptar_texto(p_correo),
        encriptar_texto(p_tarjeta_credito),
        p_fecha_expiracion,
        encriptar_texto(p_numero_seguridad)
    );
    COMMIT;
END insertar_datos_sensibles;
/

-- Vista para acceder a datos desencriptados (solo usuarios autorizados)
CREATE OR REPLACE VIEW VW_Datos_Cliente_Desencriptados AS
SELECT 
    d.ID_Datos,
    d.Fk_Cliente,
    c.Nombre || ' ' || c.Apellido AS Nombre_Completo,
    desencriptar_texto(d.Correo_Encriptado) AS Correo,
    desencriptar_texto(d.Tarjeta_Credito_Encriptado) AS Tarjeta_Credito,
    d.Fecha_Expiracion_Tarjeta,
    desencriptar_texto(d.Numero_Seguridad_Encriptado) AS Numero_Seguridad,
    d.Fecha_Registro
FROM Datos_Sensibles_Cliente d
JOIN Cliente c ON d.Fk_Cliente = c.ID_Cliente;

-- =====================================================================
-- PARTE 4: CONFIGURACIÓN DE AUDITORÍAS
-- =====================================================================

-- Auditoría de inicio y cierre de sesión (exitosos y fallidos)
AUDIT SESSION;

-- Auditoría de operaciones DML en tablas con datos sensibles
AUDIT INSERT, UPDATE, DELETE ON Datos_Sensibles_Cliente BY ACCESS;

-- Auditoría de acceso a la vista de datos desencriptados
AUDIT SELECT ON VW_Datos_Cliente_Desencriptados BY ACCESS;

-- Auditoría de operaciones en tabla Cliente (datos personales)
AUDIT INSERT, UPDATE, DELETE ON Cliente BY ACCESS;

-- Auditoría de operaciones en tabla Veterinario
AUDIT INSERT, UPDATE, DELETE ON Veterinario BY ACCESS;

-- Auditoría de transacciones financieras (Factura y Detalle_Factura)
AUDIT INSERT, UPDATE, DELETE ON Factura BY ACCESS;
AUDIT INSERT, UPDATE, DELETE ON Detalle_Factura BY ACCESS;

-- Auditoría de registros médicos
AUDIT INSERT, UPDATE ON Historial_Medico BY ACCESS;

-- Auditoría de gestión de usuarios y privilegios
AUDIT GRANT ANY PRIVILEGE;
AUDIT GRANT ANY ROLE;
AUDIT REVOKE ANY PRIVILEGE;
AUDIT REVOKE ANY ROLE;
AUDIT CREATE USER;
AUDIT ALTER USER;
AUDIT DROP USER;

-- Auditoría de ejecución de funciones de encriptación
AUDIT EXECUTE ON encriptar_texto BY ACCESS;
AUDIT EXECUTE ON desencriptar_texto BY ACCESS;

-- =====================================================================
-- PARTE 5: ROW-LEVEL SECURITY (VPD - Virtual Private Database)
-- =====================================================================
-- Implementación de seguridad a nivel de fila para control de acceso granular

-- Función de política RLS para controlar acceso a datos de clientes
-- NOTA: Los valores numéricos son ejemplos para demostración
-- En producción, estos valores deben configurarse según reglas de negocio
CREATE OR REPLACE FUNCTION fn_rls_cliente_policy (
    p_schema IN VARCHAR2,
    p_table IN VARCHAR2
) RETURN VARCHAR2 IS
    v_predicate VARCHAR2(4000);
BEGIN
    -- Administradores ven todos los registros
    IF USER = 'ADMIN_VET' OR USER = 'SYSTEM' OR USER = 'SYS' THEN
        RETURN NULL; -- Sin filtro para administradores
    
    -- Recepcionistas: acceso limitado a un subconjunto de clientes
    -- El valor 25 es un ejemplo; en producción usar tabla de asignaciones
    ELSIF USER = 'RECEPCIONISTA_VET' THEN
        RETURN 'ID_Cliente <= 25'; -- Ejemplo: primeros 25 clientes asignados
    
    -- Veterinarios ven clientes con citas asignadas a ellos
    ELSIF USER = 'USER_VET' THEN
        RETURN 'ID_Cliente IN (SELECT DISTINCT c.Fk_Cliente FROM Mascota m 
                               JOIN Cita c ON m.ID_Mascota = c.Fk_Mascota)';
    
    -- Otros usuarios no ven ningún registro
    ELSE
        RETURN '1=0';
    END IF;
END fn_rls_cliente_policy;
/

-- Función de política RLS para controlar acceso a datos sensibles
CREATE OR REPLACE FUNCTION fn_rls_datos_sensibles_policy (
    p_schema IN VARCHAR2,
    p_table IN VARCHAR2
) RETURN VARCHAR2 IS
BEGIN
    -- Solo administradores pueden ver datos sensibles
    IF USER = 'ADMIN_VET' OR USER = 'SYSTEM' OR USER = 'SYS' THEN
        RETURN NULL; -- Sin filtro para administradores
    ELSE
        RETURN '1=0'; -- Nadie más puede ver datos sensibles
    END IF;
END fn_rls_datos_sensibles_policy;
/

-- Función de política RLS para Historial Médico
-- NOTA: Esta política usa patrones de ejemplo para demostración
-- En producción, implementar mapeo usuario-veterinario en una tabla
CREATE OR REPLACE FUNCTION fn_rls_historial_policy (
    p_schema IN VARCHAR2,
    p_table IN VARCHAR2
) RETURN VARCHAR2 IS
BEGIN
    -- Administradores ven todo
    IF USER = 'ADMIN_VET' OR USER = 'SYSTEM' OR USER = 'SYS' THEN
        RETURN NULL;
    
    -- Veterinarios: en producción, usar tabla de mapeo usuario-veterinario
    -- Este ejemplo asume que el usuario veterinario tiene citas asignadas
    ELSIF USER = 'USER_VET' THEN
        RETURN 'Fk_Veterinario IN (SELECT ID_Veterinario FROM Veterinario)';
    
    -- Recepcionistas: acceso limitado para clientes asignados
    -- El valor 10 es un ejemplo; en producción usar tabla de asignaciones
    ELSIF USER = 'RECEPCIONISTA_VET' THEN
        RETURN 'Fk_Mascota IN (SELECT ID_Mascota FROM Mascota WHERE Fk_Cliente <= 10)';
    
    ELSE
        RETURN '1=0';
    END IF;
END fn_rls_historial_policy;
/

-- =====================================================================
-- PARTE 6: APLICAR POLÍTICAS RLS
-- =====================================================================
-- NOTA: Ejecutar estos bloques solo si se desea habilitar RLS

-- Política para tabla Cliente
BEGIN
    DBMS_RLS.ADD_POLICY(
        object_schema   => USER,
        object_name     => 'CLIENTE',
        policy_name     => 'POL_RLS_CLIENTE',
        function_schema => USER,
        policy_function => 'FN_RLS_CLIENTE_POLICY',
        statement_types => 'SELECT, UPDATE, DELETE',
        update_check    => TRUE,
        enable          => TRUE
    );
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE = -28101 THEN -- La política ya existe
            DBMS_OUTPUT.PUT_LINE('La política POL_RLS_CLIENTE ya existe.');
        ELSE
            RAISE;
        END IF;
END;
/

-- Política para tabla Datos_Sensibles_Cliente
BEGIN
    DBMS_RLS.ADD_POLICY(
        object_schema   => USER,
        object_name     => 'DATOS_SENSIBLES_CLIENTE',
        policy_name     => 'POL_RLS_DATOS_SENSIBLES',
        function_schema => USER,
        policy_function => 'FN_RLS_DATOS_SENSIBLES_POLICY',
        statement_types => 'SELECT, INSERT, UPDATE, DELETE',
        update_check    => TRUE,
        enable          => TRUE
    );
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE = -28101 THEN
            DBMS_OUTPUT.PUT_LINE('La política POL_RLS_DATOS_SENSIBLES ya existe.');
        ELSE
            RAISE;
        END IF;
END;
/

-- Política para tabla Historial_Medico
BEGIN
    DBMS_RLS.ADD_POLICY(
        object_schema   => USER,
        object_name     => 'HISTORIAL_MEDICO',
        policy_name     => 'POL_RLS_HISTORIAL',
        function_schema => USER,
        policy_function => 'FN_RLS_HISTORIAL_POLICY',
        statement_types => 'SELECT, UPDATE',
        update_check    => TRUE,
        enable          => TRUE
    );
EXCEPTION
    WHEN OTHERS THEN
        IF SQLCODE = -28101 THEN
            DBMS_OUTPUT.PUT_LINE('La política POL_RLS_HISTORIAL ya existe.');
        ELSE
            RAISE;
        END IF;
END;
/

-- =====================================================================
-- PARTE 7: PRIVILEGIOS PARA FUNCIONES DE ENCRIPTACIÓN
-- =====================================================================

-- Dar permiso de ejecución de funciones de encriptación a roles específicos
GRANT EXECUTE ON encriptar_texto TO Rol_Admin;
GRANT EXECUTE ON desencriptar_texto TO Rol_Admin;

-- Acceso a la tabla de datos sensibles solo para administradores
GRANT SELECT, INSERT, UPDATE, DELETE ON Datos_Sensibles_Cliente TO Rol_Admin;

-- Acceso a la vista de datos desencriptados solo para administradores
GRANT SELECT ON VW_Datos_Cliente_Desencriptados TO Rol_Admin;

-- =====================================================================
-- PARTE 8: DATOS DE PRUEBA
-- =====================================================================

-- Insertar datos de prueba encriptados para los primeros 5 clientes
BEGIN
    insertar_datos_sensibles(
        p_cliente_id => 1,
        p_correo => 'syakovlev1@quantcast.com',
        p_tarjeta_credito => '4532123456789012',
        p_fecha_expiracion => TO_DATE('2027-12-31', 'YYYY-MM-DD'),
        p_numero_seguridad => '123'
    );
    
    insertar_datos_sensibles(
        p_cliente_id => 2,
        p_correo => 'cmonery1@paginegialle.it',
        p_tarjeta_credito => '5432109876543210',
        p_fecha_expiracion => TO_DATE('2026-06-30', 'YYYY-MM-DD'),
        p_numero_seguridad => '456'
    );
    
    insertar_datos_sensibles(
        p_cliente_id => 3,
        p_correo => 'ayoxall1@51.la',
        p_tarjeta_credito => '6011123456789012',
        p_fecha_expiracion => TO_DATE('2028-03-15', 'YYYY-MM-DD'),
        p_numero_seguridad => '789'
    );
    
    insertar_datos_sensibles(
        p_cliente_id => 4,
        p_correo => 'jferrara1@booking.com',
        p_tarjeta_credito => '3782822463100052',
        p_fecha_expiracion => TO_DATE('2025-09-20', 'YYYY-MM-DD'),
        p_numero_seguridad => '012'
    );
    
    insertar_datos_sensibles(
        p_cliente_id => 5,
        p_correo => 'cughi1@google.ca',
        p_tarjeta_credito => '4111111111111111',
        p_fecha_expiracion => TO_DATE('2029-01-01', 'YYYY-MM-DD'),
        p_numero_seguridad => '345'
    );
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Error insertando datos de prueba: ' || SQLERRM);
        ROLLBACK;
END;
/

COMMIT;

-- =====================================================================
-- PARTE 9: CONSULTAS DE VERIFICACIÓN
-- =====================================================================

-- Ver datos encriptados (formato RAW)
SELECT 
    ID_Datos,
    Fk_Cliente,
    Correo_Encriptado,
    Tarjeta_Credito_Encriptado
FROM Datos_Sensibles_Cliente;

-- Ver datos desencriptados usando la vista
SELECT * FROM VW_Datos_Cliente_Desencriptados;

-- Verificar auditorías configuradas
SELECT 
    USER_NAME,
    AUDIT_OPTION,
    SUCCESS,
    FAILURE
FROM DBA_STMT_AUDIT_OPTS
ORDER BY USER_NAME, AUDIT_OPTION;

-- Ver auditorías de objetos
SELECT 
    OWNER,
    OBJECT_NAME,
    OBJECT_TYPE,
    ALT,
    AUD,
    COM,
    DEL,
    GRA,
    IND,
    INS,
    LOC,
    REN,
    SEL,
    UPD
FROM DBA_OBJ_AUDIT_OPTS
WHERE OWNER = USER
ORDER BY OBJECT_NAME;

-- Ver políticas RLS aplicadas
SELECT 
    OBJECT_OWNER,
    OBJECT_NAME,
    POLICY_NAME,
    FUNCTION,
    ENABLE,
    SEL,
    INS,
    UPD,
    DEL
FROM DBA_POLICIES
WHERE OBJECT_OWNER = USER;

-- Ver últimas 50 acciones en el trail de auditoría
SELECT
    TIMESTAMP,
    USERNAME,
    ACTION_NAME,
    OBJ_NAME,
    SQL_TEXT,
    RETURNCODE
FROM DBA_AUDIT_TRAIL
WHERE USERNAME = USER
ORDER BY TIMESTAMP DESC
FETCH FIRST 50 ROWS ONLY;

-- =====================================================================
-- PARTE 10: SCRIPTS PARA DESHABILITAR POLÍTICAS (SI ES NECESARIO)
-- =====================================================================
-- Estos comandos solo deben ejecutarse si se necesita deshabilitar las políticas

/*
-- Deshabilitar política de Cliente
BEGIN
    DBMS_RLS.DROP_POLICY(
        object_schema => USER,
        object_name   => 'CLIENTE',
        policy_name   => 'POL_RLS_CLIENTE'
    );
END;
/

-- Deshabilitar política de Datos Sensibles
BEGIN
    DBMS_RLS.DROP_POLICY(
        object_schema => USER,
        object_name   => 'DATOS_SENSIBLES_CLIENTE',
        policy_name   => 'POL_RLS_DATOS_SENSIBLES'
    );
END;
/

-- Deshabilitar política de Historial Médico
BEGIN
    DBMS_RLS.DROP_POLICY(
        object_schema => USER,
        object_name   => 'HISTORIAL_MEDICO',
        policy_name   => 'POL_RLS_HISTORIAL'
    );
END;
/

-- Deshabilitar auditorías
NOAUDIT SESSION;
NOAUDIT ALL ON Datos_Sensibles_Cliente;
NOAUDIT ALL ON Cliente;
NOAUDIT ALL ON Veterinario;
NOAUDIT ALL ON Factura;
NOAUDIT ALL ON Detalle_Factura;
NOAUDIT ALL ON Historial_Medico;
NOAUDIT SELECT ON VW_Datos_Cliente_Desencriptados;
*/

-- =====================================================================
-- FIN DEL SCRIPT DE SEGURIDAD
-- =====================================================================
