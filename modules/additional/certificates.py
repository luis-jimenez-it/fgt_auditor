# modules/additional/certificates.py
import re

def audit(ctx):
    """
    Auditoría del subsistema de Certificados y PKI conforme a la línea base
    corporativa SEG-LNB-002 (Hardening y Criptografía).
    """
    checks = []
    raw_content = ctx.get('content', '')
    raw_content = raw_content.replace('\xa0', ' ')

    # Extraer bloques de certificados locales (config vpn certificate local o config certificate local)
    cert_match = re.search(r'config certificate local(.*?)(?:\nend|\Z)', raw_content, re.DOTALL | re.IGNORECASE)
    cert_block = cert_match.group(1) if cert_match else ""

    # Contar certificados locales configurados
    local_certs = re.findall(r'edit\s+"?([^"\n]+)"?', cert_block, re.IGNORECASE)
    has_custom_certs = len(local_certs) > 0

    # =========================================================================
    # CHECK 1: Uso de Certificados Personalizados / PKI Corporativa
    # =========================================================================
    checks.append({
        'id': 'CHK-CERT-LOCAL',
        'vdom': 'global',
        'cat': 'System Hardening',
        'mod': 'Certificates and PKI - Local Certificates',
        'hallazgo': f"Gestión de Certificados: {'Se encontraron certificados locales configurados (' + ', '.join(local_certs) + ')' if has_custom_certs else 'No se detectaron certificados locales personalizados, operando potencialmente con los certificados autofirmados por defecto de Fortinet'}",
        'estado': 'PASS' if has_custom_certs else 'WARNING',
        'sev': 'Media',
        'peso': 5,
        'afectados': f"Global -> Certificados locales: {local_certs if local_certs else 'Ninguno'}",
        'evidencia': f"Certificados locales detectados: {local_certs}",
        'rec': 'Reemplazar los certificados autofirmados por defecto del fabricante por certificados legítimos emitidos por la CA corporativa o pública conforme a SEG-LNB-002.',
        'rem': 'config certificate local\n  edit "Cert_Corporativo"\n    set enrollment file\n  next\nend',
        'tipo': 'Criptografía',
        'ref': 'SEG-LNB-002 Num 6.7 y 6.10'
    })

    return checks
