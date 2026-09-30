# modules/policy_objects/firewall_policy.py
import re

def extract_nested_block(text, block_header):
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line == block_header:
            block_lines = []
            i += 1
            nesting = 1
            while i < len(lines):
                sub_s = lines[i].strip()
                if sub_s.startswith("config ") or sub_s.startswith("edit "):
                    nesting += 1
                elif sub_s in ["end", "next"]:
                    nesting -= 1
                    if nesting == 0:
                        break
                block_lines.append(lines[i])
                i += 1
            return "\n".join(block_lines)
        i += 1
    return None

def audit(ctx):
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    if not vdom_blocks:
        vdom_blocks = {'root': ctx.get('content', '')}

    for vdom_name, vdom_content in vdom_blocks.items():
        fw_block = extract_nested_block(vdom_content, "config firewall policy")
        if not fw_block:
            continue

        policies_raw = re.findall(r'edit (\d+)(.*?)(?=\n\s*edit \d+|\Z)', fw_block, re.DOTALL)
        if not policies_raw:
            continue

        disabled_list = []
        no_utm_list = []
        src_all_list = []
        dst_all_internal_list = []
        pass_list = []

        for p_id, p_body in policies_raw:
            name_m = re.search(r'set name\s+"([^"]+)"', p_body)
            p_name = name_m.group(1) if name_m else f"Regla_{p_id}"
            
            status_m = re.search(r'set status\s+([a-z]+)', p_body)
            status = status_m.group(1) if status_m else "enable"

            action_m = re.search(r'set action\s+([a-z]+)', p_body)
            action = action_m.group(1) if action_m else "accept"

            srcintf_m = re.search(r'set srcintf\s+([^\n]+)', p_body)
            dstintf_m = re.search(r'set dstintf\s+([^\n]+)', p_body)
            src_m = re.search(r'set srcaddr\s+([^\n]+)', p_body)
            dst_m = re.search(r'set dstaddr\s+([^\n]+)', p_body)

            srcintf = srcintf_m.group(1).strip() if srcintf_m else ""
            dstintf = dstintf_m.group(1).strip() if dstintf_m else ""
            srcaddr = src_m.group(1).strip() if src_m else ""
            dstaddr = dst_m.group(1).strip() if dst_m else ""

            tag = f"ID {p_id} ('{p_name}')"
            has_issue = False

            if status == "disable":
                disabled_list.append(tag)
                has_issue = True

            if action == "accept":
                utm_profiles = ['av-profile', 'webfilter-profile', 'ips-sensor', 'application-list', 'dlp-sensor', 'emailfilter-profile', 'icap-profile']
                has_utm = any(re.search(rf'set {prof}\s+"?[^"]+"?', p_body) for prof in utm_profiles)
                if not has_utm:
                    no_utm_list.append(tag)
                    has_issue = True

                if '"all"' in srcaddr.lower() or srcaddr.lower() == 'all':
                    src_all_list.append(tag)
                    has_issue = True

                is_dst_all = ('"all"' in dstaddr.lower() or dstaddr.lower() == 'all')
                is_wan_destination = any(w in dstintf.lower() for w in ['wan', 'ext', 'internet', 'outside', 'public', 'virtual-wan-link'])
                if is_dst_all and not is_wan_destination:
                    dst_all_internal_list.append(tag)
                    has_issue = True

            if not has_issue:
                pass_list.append(p_id)

        vdom_prefix = vdom_name.upper().replace('-', '_')

        checks.append({
            'id': f'CHK-POL-SUMMARY-{vdom_prefix}-DISABLED',
            'vdom': vdom_name,
            'cat': 'Políticas y Objetos',
            'mod': 'Firewall Policy (Resumen)',
            'hallazgo': f"VDOM '{vdom_name}': Políticas deshabilitadas (Total: {len(disabled_list)})",
            'estado': 'WARNING' if disabled_list else 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Políticas: {', '.join(disabled_list) if disabled_list else 'Ninguna'}",
            'evidencia': f"IDs deshabilitados: {', '.join(disabled_list) if disabled_list else 'N/A'}",
            'rec': 'Depurar y eliminar políticas deshabilitadas obsoletas.',
            'rem': 'config firewall policy \n  delete <ID>\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5'
        })

        checks.append({
            'id': f'CHK-POL-SUMMARY-{vdom_prefix}-NO-UTM',
            'vdom': vdom_name,
            'cat': 'Políticas y Objetos',
            'mod': 'Firewall Policy (Resumen)',
            'hallazgo': f"VDOM '{vdom_name}': Políticas con action accept sin perfiles UTM (Total: {len(no_utm_list)})",
            'estado': 'FAIL' if no_utm_list else 'PASS',
            'sev': 'Alta',
            'peso': 10,
            'afectados': f"VDOM {vdom_name} -> Políticas: {', '.join(no_utm_list) if no_utm_list else 'Ninguna'}",
            'evidencia': f"IDs sin UTM: {', '.join(no_utm_list) if no_utm_list else 'N/A'}",
            'rec': 'Asociar perfiles de inspección de seguridad (AV, IPS, Webfilter) a las políticas activas.',
            'rem': 'config firewall policy \n  edit <ID>\n    set utm-status enable\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5'
        })

        checks.append({
            'id': f'CHK-POL-SUMMARY-{vdom_prefix}-SRC-ALL',
            'vdom': vdom_name,
            'cat': 'Políticas y Objetos',
            'mod': 'Firewall Policy (Resumen)',
            'hallazgo': f"VDOM '{vdom_name}': Políticas con origen 'all' (Total: {len(src_all_list)})",
            'estado': 'FAIL' if src_all_list else 'PASS',
            'sev': 'Alta',
            'peso': 10,
            'afectados': f"VDOM {vdom_name} -> Políticas: {', '.join(src_all_list) if src_all_list else 'Ninguna'}",
            'evidencia': f"IDs con src 'all': {', '.join(src_all_list) if src_all_list else 'N/A'}",
            'rec': 'Restringir el origen a subredes específicas bajo el principio de menor privilegio.',
            'rem': 'config firewall policy \n  edit <ID>\n    set srcaddr "<Subred>"\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5'
        })

        checks.append({
            'id': f'CHK-POL-SUMMARY-{vdom_prefix}-DST-ALL-INTERNAL',
            'vdom': vdom_name,
            'cat': 'Políticas y Objetos',
            'mod': 'Firewall Policy (Resumen)',
            'hallazgo': f"VDOM '{vdom_name}': Políticas con destino 'all' hacia red interna (Total: {len(dst_all_internal_list)})",
            'estado': 'FAIL' if dst_all_internal_list else 'PASS',
            'sev': 'Alta',
            'peso': 10,
            'afectados': f"VDOM {vdom_name} -> Políticas: {', '.join(dst_all_internal_list) if dst_all_internal_list else 'Ninguna'}",
            'evidencia': f"IDs destino all interno: {', '.join(dst_all_internal_list) if dst_all_internal_list else 'N/A'}",
            'rec': 'Acatar segmentación interna restringiendo el destino a objetos específicos.',
            'rem': 'config firewall policy \n  edit <ID>\n    set dstaddr "<Destino>"\n  next\nend',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5'
        })

        pass_summary = f"IDs correctos: {', '.join(pass_list)}" if pass_list else "Ninguna política cumple con el estándar completo"
        checks.append({
            'id': f'CHK-POL-SUMMARY-{vdom_prefix}-PASS',
            'vdom': vdom_name,
            'cat': 'Políticas y Objetos',
            'mod': 'Firewall Policy (Resumen)',
            'hallazgo': f"VDOM '{vdom_name}': Políticas correctamente configuradas y limpias (Total: {len(pass_list)})",
            'estado': 'PASS',
            'sev': 'Baja',
            'peso': 5,
            'afectados': f"VDOM {vdom_name} -> Total correctas: {len(pass_list)}",
            'evidencia': pass_summary[:250] + "..." if len(pass_summary) > 250 else pass_summary,
            'rec': 'Mantener las buenas prácticas de segmentación y control.',
            'rem': 'N/A - Cumple',
            'tipo': 'Técnico',
            'ref': 'SEG-LNB-002 Num 6.5'
        })

    return checks
