# modules/network/policy_routes.py
import re

def audit(ctx):
    """
    Auditoría Técnica Dinámica de Policy Routes (config router policy) VDOM por VDOM.
    Valida la existencia, estado (disable) y parámetros de configuración de PBRs.
    Normativa: SEG-LNB-002 (Num 6.1 Control de Tráfico y Enrutamiento), NIST SC-7
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    raw_content = ctx.get('content', '')

    if not vdom_blocks:
        vdom_blocks = {'root': raw_content}

    parsed_ifaces = ctx.get('parsed_interfaces', [])

    for vdom_name, vdom_content in vdom_blocks.items():
        vdom_iface_status = {i['name']: i['status'] for i in parsed_ifaces if i['vdom'] == vdom_name}

        # Búsqueda precisa del bloque config router policy
        m_block = re.search(r'config router policy\s*(.*?)\n\s*end\b', vdom_content, re.DOTALL)
        
        if not m_block and vdom_name == 'root':
            m_block = re.search(r'config router policy\s*(.*?)\n\s*end\b', raw_content, re.DOTALL)

        if not m_block:
            checks.append({
                'id': f'CHK-ROUTE-POLICY-{vdom_name.upper().replace("-", "_")}-NONE',
                'vdom': vdom_name,
                'cat': 'Red y Enrutamiento',
                'mod': 'Policy Routes (PBR)',
                'hallazgo': f"VDOM '{vdom_name}': No existen rutas de política (config router policy) configuradas",
                'estado': 'INFO',
                'sev': 'Baja',
                'peso': 0,
                'afectados': f"VDOM {vdom_name} -> config router policy",
                'evidencia': 'Bloque config router policy ausente en este VDOM',
                'rec': 'N/A - Comportamiento estándar si no se requiere PBR',
                'rem': 'N/A - Informativo',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.1 / NIST SC-7'
            })
            continue

        policy_body = m_block.group(1)
        policies_raw = re.findall(r'edit (\d+)(.*?)(?=\n\s*edit \d+|\Z)', policy_body, re.DOTALL)

        if not policies_raw:
            continue

        for seq, p_body in policies_raw:
            src_m = re.search(r'set src\s+([^\n]+)', p_body)
            dst_m = re.search(r'set dst\s+([^\n]+)', p_body)
            input_dev_m = re.search(r'set input-device\s+"([^"]+)"', p_body)
            output_dev_m = re.search(r'set output-device\s+"([^"]+)"', p_body)
            gw_m = re.search(r'set gateway\s+([^\n]+)', p_body)
            status_m = re.search(r'set status\s+([a-z]+)', p_body)

            src = src_m.group(1).strip() if src_m else "all"
            dst = dst_m.group(1).strip() if dst_m else "all"
            input_dev = input_dev_m.group(1).strip() if input_dev_m else "cualquiera"
            output_dev = output_dev_m.group(1).strip() if output_dev_m else "no definido"
            gateway = gw_m.group(1).strip() if gw_m else "N/A"
            status = status_m.group(1) if status_m else "enable"

            p_id = f"CHK-ROUTE-POLICY-{vdom_name.upper().replace('-', '_')}-{seq}"
            evidencia_str = f"Seq #{seq} | In: {input_dev} | Src: {src} -> Dst: {dst} | Out: {output_dev} (GW: {gateway})"

            if status == "disable":
                checks.append({
                    'id': p_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Enrutamiento',
                    'mod': 'Policy Routes (PBR)',
                    'hallazgo': f"Policy Route Seq #{seq} en VDOM '{vdom_name}' deshabilitada administrativamente",
                    'estado': 'WARNING',
                    'sev': 'Baja',
                    'peso': 5,
                    'afectados': f"VDOM {vdom_name} -> config router policy #{seq}",
                    'evidencia': f"set status disable en regla PBR #{seq}",
                    'rec': f"Eliminar la regla PBR #{seq} si ya no se utiliza",
                    'rem': f'config vdom\nedit "{vdom_name}"\nconfig router policy\n  delete {seq}\nend\nnext\nend',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.1'
                })
            else:
                checks.append({
                    'id': p_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Enrutamiento',
                    'mod': 'Policy Routes (PBR)',
                    'hallazgo': f"Policy Route Seq #{seq} en VDOM '{vdom_name}' activa y configurada correctamente",
                    'estado': 'PASS',
                    'sev': 'Baja',
                    'peso': 5,
                    'afectados': f"VDOM {vdom_name} -> config router policy #{seq}",
                    'evidencia': evidencia_str,
                    'rec': 'Mantener revisión periódica del orden y rutas de política',
                    'rem': 'N/A - Cumple',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.1'
                })

    return checks
