# modules/additional/advanced_threats.py
import re

def audit(ctx):
    """
    Auditoría de Protección Avanzada e Inteligencia de Amenazas (FortiSandbox / CTI)
    conforme a la línea base corporativa SEG-LNB-002 (Secciones 6.12 y 6.13).
    """
    checks = []
    raw_content = ctx.get('content', '')
    raw_content = raw_content.replace('\xa0', ' ')

    # 1. Verificar configuración de FortiSandbox (config system fortisandbox)
    fsb_match = re.search(r'config system fortisandbox(.*?)(?:\nend|\Z)', raw_content, re.DOTALL | re.IGNORECASE)
    fsb_block = fsb_match.group(1) if fsb_match else ""
    fsb_enabled = False
    if fsb_block and re.search(r'^\s*set\s+status\s+enable', fsb_block, re.IGNORECASE | re.MULTILINE):
        fsb_enabled = True

    # =========================================================================
    # CHECK 1: Integración con FortiSandbox (SEG-LNB-002 Num 6.13)
    # =========================================================================
    checks.append({
        'id': 'CHK-ADV-FORTISANDBOX',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'Advanced Protection - FortiSandbox Integration',
        'hallazgo': f"Protección Avanzada: {'La integración con FortiSandbox se encuentra habilitada' if fsb_enabled else 'No se encuentra configurado o habilitado el servicio de FortiSandbox para detección de amenazas desconocidas (Zero-Day)'}",
        'estado': 'PASS' if fsb_enabled else 'WARNING',
        'sev': 'Media',
        'peso': 5,
        'afectados': f"Global -> FortiSandbox status: {'Habilitado' if fsb_enabled else 'Deshabilitado'}",
        'evidencia': f"FortiSandbox habilitado: {fsb_enabled}",
        'rec': 'Utilizar FortiSandbox cuando esté disponible para la detección y mitigación de amenazas avanzadas y zero-day conforme a SEG-LNB-002.',
        'rem': 'config system fortisandbox\n  set status enable\n  set server "IP_O_FQDN_SANDBOX"\nend',
        'tipo': 'Arquitectura',
        'ref': 'SEG-LNB-002 Num 6.13[cite: 1]'
    })

    return checks
