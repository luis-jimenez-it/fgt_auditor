# modules/system/updates.py
import re
import urllib.request
import urllib.error

def fetch_cves_online(version):
    """
    Consulta la base de datos de cybersecurity-help.cz para obtener CVEs de la versión de FortiOS.
    """
    url = f"https://www.cybersecurity-help.cz/vdb/soft/fortinet/fortios/{version}/"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    req = urllib.request.Request(url, headers=headers)
    
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            html = response.read().decode('utf-8', errors='ignore')
            cves = sorted(list(set(re.findall(r'CVE-\d{4}-\d+', html))))
            return {
                'status': 'ok',
                'url': url,
                'cves': cves,
                'count': len(cves)
            }
    except Exception as e:
        return {
            'status': 'error',
            'url': url,
            'cves': [],
            'count': 0,
            'msg': str(e)
        }

def audit(ctx):
    """
    Auditoría de Firmware y Vulnerabilidades (CVEs)
    Normativa: SEG-LNB-002 (Num 6.2 Actualizaciones y Parches), ISO 27001 A.12.6.1, NIST SI-2
    """
    checks = []
    metadata = ctx.get('metadata', {})
    raw_ver = metadata.get('Version_Number', '7.4.8')
    fw_desc = metadata.get('Firmware', f'FortiOS v{raw_ver}')

    # Consultar vulnerabilidades en línea
    cve_data = fetch_cves_online(raw_ver)

    if cve_data['status'] == 'ok' and cve_data['count'] > 0:
        cves_sample = cve_data['cves'][:6]
        checks.append({
            'id': 'CHK-UPD-CVE-VULN',
            'vdom': 'Global',
            'cat': 'Actualizaciones y Parches',
            'mod': 'Firmware & Autoupdate',
            'hallazgo': f"Se identificaron {cve_data['count']} vulnerabilidades conocidas (CVEs) en FortiOS {raw_ver}",
            'estado': 'FAIL',
            'sev': 'Crítica',
            'peso': 15,
            'afectados': f"Firmware del Sistema ({raw_ver})",
            'evidencia': f"CVEs detectados: {', '.join(cves_sample)}... (Fuente: {cve_data['url']})",
            'rec': 'Actualizar de inmediato a una versión de parche reciente (ej. FortiOS v7.4.11 o v7.4.12) para mitigar vulnerabilidades críticas',
            'rem': f'Revisar notas de versión y actualizar desde consola o FortiCloud a la última release segura de la rama {raw_ver.rsplit(".", 1)[0]}',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.2 / ISO 27001 A.12.6.1 / NIST SI-2'
        })
    elif cve_data['status'] == 'ok' and cve_data['count'] == 0:
        checks.append({
            'id': 'CHK-UPD-CVE-VULN',
            'vdom': 'Global',
            'cat': 'Actualizaciones y Parches',
            'mod': 'Firmware & Autoupdate',
            'hallazgo': f"No se reportan vulnerabilidades públicas sin parchear para la versión {raw_ver}",
            'estado': 'PASS',
            'sev': 'Alta',
            'peso': 10,
            'afectados': 'FortiOS System',
            'evidencia': f"Consulta exitosa sin CVEs activos en {cve_data['url']}",
            'rec': 'Mantener el firmware actualizado y monitorear avisos PSIRT',
            'rem': 'N/A - Cumple',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.2 / ISO 27001 A.12.6.1 / NIST SI-2'
        })
    else:
        # Fallback si el servidor no tiene salida a Internet momentáneamente
        checks.append({
            'id': 'CHK-UPD-CVE-VULN',
            'vdom': 'Global',
            'cat': 'Actualizaciones y Parches',
            'mod': 'Firmware & Autoupdate',
            'hallazgo': f"Firmware evaluado localmente: {fw_desc} (Consulta online no disponible)",
            'estado': 'WARNING',
            'sev': 'Media',
            'peso': 5,
            'afectados': 'FortiOS System',
            'evidencia': f"No se pudo consultar {cve_data['url']} ({cve_data.get('msg', 'Timeout')})",
            'rec': 'Verificar manualmente los boletines de seguridad para la versión instalada',
            'rem': 'Verificar conectividad a Internet desde el servidor auditor',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.2 / NIST SI-2'
        })

    return checks
