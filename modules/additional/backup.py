# modules/additional/backup.py
import re

def audit(ctx):
    """
    Auditoría estricta del subsistema de Respaldo y Recuperación (config system backup)
    conforme a la línea base corporativa SEG-LNB-002 (Sección 6.9).
    """
    checks = []
    raw_content = ctx.get('content', '')
    raw_content = raw_content.replace('\xa0', ' ')

    # Extraer el bloque automation-stitch
    stitch_match = re.search(r'config system automation-stitch(.*?)^\s*end', raw_content, re.DOTALL | re.IGNORECASE | re.MULTILINE)
    stitch_block = stitch_match.group(1) if stitch_match else ""

    auto_backup_configured = False
    
    if stitch_block:
        # Extraer los bloques "edit" (stitches) activos (que NO tengan set status disable)
        stitches = re.finditer(r'edit\s+"[^"]+"(.*?)next', stitch_block, re.DOTALL | re.IGNORECASE)
        for stitch in stitches:
            stitch_content = stitch.group(1)
            # Descartar los que están explícitamente deshabilitados
            if re.search(r'^\s*set\s+status\s+disable', stitch_content, re.IGNORECASE | re.MULTILINE):
                continue
            
            # Buscar si el stitch activo invoca una acción de backup de configuración
            if re.search(r'set\s+action\s+"?[^"]*backup[^"]*"?', stitch_content, re.IGNORECASE):
                auto_backup_configured = True
                break

    # =========================================================================
    # CHECK 1: Respaldos Automáticos y Externos (SEG-LNB-002 Num 6.9)
    # =========================================================================
    checks.append({
        'id': 'CHK-BACKUP-AUTOMATED',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'Backup and Recovery - Automated Backups',
        'hallazgo': f"Configuración de Respaldo: {'Se detectaron tareas activas de respaldo automático (Automation Stitches)' if auto_backup_configured else 'No se detectaron tareas automatizadas nativas (Automation Stitches) habilitadas de respaldo periódico hacia repositorios externos'}",
        'estado': 'PASS' if auto_backup_configured else 'WARNING',
        'sev': 'Alta',
        'peso': 8,
        'afectados': f"Global -> Automation Backup: {'Activo' if auto_backup_configured else 'Deshabilitado / No detectado'}",
        'evidencia': f"Automation backup stitch activo detectado: {auto_backup_configured}",
        'rec': 'Los backups deberán realizarse de forma automática y almacenarse en repositorios externos seguros conforme a SEG-LNB-002.',
        'rem': 'config system automation-stitch\n  edit "Auto_Backup_SCP"\n    set status enable\n    set trigger "periodic"\n    set action "backup-config"\n  next\nend',
        'tipo': 'Arquitectura',
        'ref': 'SEG-LNB-002 Num 6.9[cite: 1]'
    })

    return checks
