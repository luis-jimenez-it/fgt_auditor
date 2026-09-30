# modules/network/dns.py
import re

def audit(ctx):
    checks = []
    content = ctx.get('content', '')
    metadata = ctx.get('metadata', {})
    current_vdom = metadata.get('VDOM', 'root')

    dns_match = re.search(r'config system dns\s*(.*?)end', content, re.DOTALL)
    dns_block = dns_match.group(1) if dns_match else ""

    primary_m = re.search(r'set primary\s+([^\n]+)', dns_block)
    secondary_m = re.search(r'set secondary\s+([^\n]+)', dns_block)
    protocol_m = re.search(r'set protocol\s+([^\n]+)', dns_block)
    domain_m = re.search(r'set domain\s+"([^"]+)"', dns_block)

    primary = primary_m.group(1).strip() if primary_m else "No configurado"
    secondary = secondary_m.group(1).strip() if secondary_m else "No configurado"
    protocol = protocol_m.group(1).strip() if protocol_m else "cleartext"
    domain = domain_m.group(1) if domain_m else ""

    # CHECK 1: Protocolo DoT
    if "cleartext" in protocol:
        checks.append({
            'id': 'CHK-NET-DNS-01',
            'vdom': current_vdom,
            'cat': 'Hardening Adicional del Sistema',
            'mod': 'Servicios de Red (DNS, NTP, DHCP)',
            'hallazgo': f"Protocolo DNS configurado permitiendo texto claro ('{protocol}')",
            'estado': 'FAIL',
            'sev': 'Media',
            'peso': 5,
            'afectados': 'config system dns',
            'evidencia': f"set protocol {protocol}",
            'rec': 'Forzar DNS sobre TLS (DoT) para impedir espionaje e intercepción',
            'rem': 'config system dns\n  set protocol dot\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.10 / NIST SC-8'
        })
    else:
        checks.append({
            'id': 'CHK-NET-DNS-01',
            'vdom': current_vdom,
            'cat': 'Hardening Adicional del Sistema',
            'mod': 'Servicios de Red (DNS, NTP, DHCP)',
            'hallazgo': 'Resolución DNS protegida mediante cifrado DoT (DNS over TLS)',
            'estado': 'PASS',
            'sev': 'Media',
            'peso': 5,
            'afectados': 'config system dns',
            'evidencia': f"set protocol {protocol}",
            'rec': 'Mantener cifrado DoT activo',
            'rem': 'N/A - Cumple',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.10 / NIST SC-8'
        })

    # CHECK 2: Redundancia DNS
    if primary != "No configurado" and secondary != "No configurado":
        checks.append({
            'id': 'CHK-NET-DNS-02',
            'vdom': current_vdom,
            'cat': 'Hardening Adicional del Sistema',
            'mod': 'Servicios de Red (DNS, NTP, DHCP)',
            'hallazgo': f"Servidores DNS con redundancia configurados ({primary}, {secondary})",
            'estado': 'PASS',
            'sev': 'Media',
            'peso': 5,
            'afectados': 'config system dns',
            'evidencia': f"Primario: {primary} | Secundario: {secondary}",
            'rec': 'Mantener redundancia de servidores DNS',
            'rem': 'N/A - Cumple',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.10 / ISO 27001 A.17.2.1 / NIST CP-10'
        })

    # CHECK 3: Sufijo / Dominio DNS
    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))
    if is_ip:
        checks.append({
            'id': 'CHK-NET-DNS-03',
            'vdom': current_vdom,
            'cat': 'Hardening Adicional del Sistema',
            'mod': 'Servicios de Red (DNS, NTP, DHCP)',
            'hallazgo': f"Sufijo de búsqueda de dominio DNS configurado como dirección IP ('{domain}')",
            'estado': 'WARNING',
            'sev': 'Baja',
            'peso': 5,
            'afectados': 'config system dns',
            'evidencia': f'set domain "{domain}"',
            'rec': 'Asignar un nombre de dominio corporativo válido (FQDN)',
            'rem': 'config system dns\n  set domain "empresa.local"\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.10'
        })

    # CHECK 4: Perfiles de Filtrado DNS
    has_dnsfilter = bool(re.search(r'config dnsfilter profile', content))
    checks.append({
        'id': 'CHK-NET-DNS-04',
        'vdom': current_vdom,
        'cat': 'Servicios de Seguridad',
        'mod': 'Servicios UTM (AV, IPS, SSL)',
        'hallazgo': 'Perfiles de filtrado DNS (DNS Filter) definidos en el firewall' if has_dnsfilter else 'Ausencia de perfiles DNS Filter',
        'estado': 'PASS' if has_dnsfilter else 'WARNING',
        'sev': 'Alta',
        'peso': 10,
        'afectados': 'config dnsfilter profile',
        'evidencia': 'Perfil DNS Filter presente' if has_dnsfilter else 'Sin perfil DNS Filter',
        'rec': 'Aplicar perfiles DNS Filter en políticas salientes',
        'rem': 'N/A - Cumple' if has_dnsfilter else 'config dnsfilter profile\nedit "default"\nnext\nend',
        'tipo': 'Técnico',
        'ref': 'SEG-LNB-002 Num 6.5 / ISO 27001 A.12.2.1 / ISO 27001 A.13.2.1 / NIST SI-4'
    })

    return checks
