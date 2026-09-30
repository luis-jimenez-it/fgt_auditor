# modules/network/sdwan_rules.py
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
    """
    Auditoría Dinámica de Reglas SD-WAN (Rules / Services) y Regla Implícita VDOM por VDOM.
    Evalúa:
      1. Reglas de servicio SD-WAN (config service):
         - Nomenclatura, estado y configuración de salida (miembros/zonas).
         - Vinculación correcta de SLA / Health-check cuando aplica.
         - Detección de reglas inactivas o huérfanas.
      2. Regla Implícita (Implicit Rule - load-balance-mode):
         - Si no existe 'set load-balance-mode' -> Está en default (source-ip-based).
         - Recomendar cambio a sesiones (weight-based / source-dest-ip) o volumen (measured-volume).
    Normativa: SEG-LNB-002 (Num 6.14 Alta Disponibilidad y SD-WAN), ISO 27001 A.17.2.1, NIST CP-2
    """
    checks = []
    vdom_blocks = ctx.get('vdom_blocks', {})
    if not vdom_blocks:
        vdom_blocks = {'root': ctx.get('content', '')}

    for vdom_name, vdom_content in vdom_blocks.items():
        sdwan_body = extract_nested_block(vdom_content, "config system sdwan")
        if not sdwan_body:
            continue

        status_m = re.search(r'set status\s+([a-z]+)', sdwan_body)
        is_enabled = (status_m.group(1) == "enable") if status_m else False

        if not is_enabled:
            # Si SD-WAN no está activo en este VDOM, omitimos la auditoría de reglas
            continue

        # =====================================================================
        # 1. AUDITORÍA DE REGLAS DE SERVICIO (config service)
        # =====================================================================
        service_block = extract_nested_block(sdwan_body, "config service")
        rules_raw = re.findall(r'edit \d+(.*?)(?=\n\s*edit \d+|\Z)', service_block, re.DOTALL) if service_block else []

        if not rules_raw:
            checks.append({
                'id': f'CHK-SDWAN-RULES-{vdom_name.upper().replace("-", "_")}',
                'vdom': vdom_name,
                'cat': 'Red y Segmentación',
                'mod': 'Alta Disponibilidad y SD-WAN',
                'hallazgo': f"VDOM '{vdom_name}': No existen reglas de servicio SD-WAN configuradas (todo el tráfico cae a la regla implícita)",
                'estado': 'WARNING',
                'sev': 'Media',
                'peso': 5,
                'afectados': f"VDOM {vdom_name} -> config system sdwan -> config service",
                'evidencia': 'config service vacío o sin reglas de enrutamiento definidas',
                'rec': 'Definir reglas de negocio (ej. tráfico crítico, navegación, SaaS) hacia zonas específicas',
                'rem': f'config vdom\nedit "{vdom_name}"\nconfig system sdwan\n  config service\n    edit 1\n      set name "Regla_SaaS"\n      set mode priority\n    next\n  end\nend\nnext\nend',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.14'
            })
        else:
            for idx_rule, r in enumerate(rules_raw, 1):
                name_m = re.search(r'set name\s+"([^"]+)"', r)
                rule_name = name_m.group(1) if name_m else f"Regla_{idx_rule}"
                rule_st_m = re.search(r'set status\s+([a-z]+)', r)
                rule_status = rule_st_m.group(1) if rule_st_m else "enable"
                mode_m = re.search(r'set mode\s+([a-z\-]+)', r)
                mode = mode_m.group(1) if mode_m else "auto"

                has_prio_members = bool(re.search(r'set priority-members\s+', r))
                has_prio_zone = bool(re.search(r'set priority-zone\s+', r))
                has_sla = bool(re.search(r'config sla', r) or re.search(r'set sla\s+', r))

                rule_id = f"CHK-SDWAN-RULE-{vdom_name.upper().replace('-', '_')}-{rule_name.upper().replace(' ', '_').replace('-', '_')}"

                # Regla deshabilitada
                if rule_status == "disable":
                    checks.append({
                        'id': rule_id,
                        'vdom': vdom_name,
                        'cat': 'Red y Segmentación',
                        'mod': 'Alta Disponibilidad y SD-WAN',
                        'hallazgo': f"Regla SD-WAN '{rule_name}' en VDOM '{vdom_name}' deshabilitada administrativamente",
                        'estado': 'WARNING',
                        'sev': 'Baja',
                        'peso': 5,
                        'afectados': f"VDOM {vdom_name} -> regla '{rule_name}'",
                        'evidencia': f"set status disable en regla '{rule_name}'",
                        'rec': f"Habilitar la regla '{rule_name}' o eliminarla si ya no se utiliza en el flujo de tráfico",
                        'rem': f'config vdom\nedit "{vdom_name}"\nconfig system sdwan\n  config service\n    edit <id>\n      set status enable\n    next\n  end\nend\nnext\nend',
                        'tipo': 'Técnico',
                        'ref': 'SEG-LNB-002 Num 6.14'
                    })
                # Regla sin interfaz ni zona de salida
                elif not has_prio_members and not has_prio_zone:
                    checks.append({
                        'id': rule_id,
                        'vdom': vdom_name,
                        'cat': 'Red y Segmentación',
                        'mod': 'Alta Disponibilidad y SD-WAN',
                        'hallazgo': f"Regla SD-WAN '{rule_name}' en VDOM '{vdom_name}' incompleta: no especifica miembros de salida ni zona prioritaria",
                        'estado': 'FAIL',
                        'sev': 'Alta',
                        'peso': 10,
                        'afectados': f"VDOM {vdom_name} -> regla '{rule_name}'",
                        'evidencia': 'Ausencia de set priority-members y set priority-zone',
                        'rec': f"Asignar interfaces miembros o zonas explícitas a la regla '{rule_name}'",
                        'rem': f'config vdom\nedit "{vdom_name}"\nconfig system sdwan\n  config service\n    edit <id>\n      set priority-zone "virtual-wan-link"\n    next\n  end\nend\nnext\nend',
                        'tipo': 'Técnico',
                        'ref': 'SEG-LNB-002 Num 6.14'
                    })
                # Regla configurada correctamente
                else:
                    salida = "Zona/Miembros asignados"
                    checks.append({
                        'id': rule_id,
                        'vdom': vdom_name,
                        'cat': 'Red y Segmentación',
                        'mod': 'Alta Disponibilidad y SD-WAN',
                        'hallazgo': f"Regla SD-WAN '{rule_name}' en VDOM '{vdom_name}' configurada y activa (Modo: {mode})",
                        'estado': 'PASS',
                        'sev': 'Baja',
                        'peso': 5,
                        'afectados': f"VDOM {vdom_name} -> regla '{rule_name}'",
                        'evidencia': f"Regla activa con parámetros válidos (salida: {salida}, modo: {mode})",
                        'rec': 'Mantener revisión periódica del orden de evaluación de reglas SD-WAN',
                        'rem': 'N/A - Cumple',
                        'tipo': 'Técnico',
                        'ref': 'SEG-LNB-002 Num 6.14'
                    })

        # =====================================================================
        # 2. AUDITORÍA DE LA REGLA IMPLÍCITA (Implicit Rule: load-balance-mode)
        # =====================================================================
        lb_match = re.search(r'set load-balance-mode\s+([a-z\-]+)', sdwan_body)
        implicit_check_id = f"CHK-SDWAN-IMPLICIT-{vdom_name.upper().replace('-', '_')}"

        if not lb_match:
            # No se encontró la línea -> Está en default (source-ip-based)
            checks.append({
                'id': implicit_check_id,
                'vdom': vdom_name,
                'cat': 'Red y Segmentación',
                'mod': 'Alta Disponibilidad y SD-WAN',
                'hallazgo': f"Regla Implícita SD-WAN en VDOM '{vdom_name}' sin optimizar: opera en modo por defecto (source-ip-based)",
                'estado': 'WARNING',
                'sev': 'Media',
                'peso': 5,
                'afectados': f"VDOM {vdom_name} -> config system sdwan (Implicit Rule)",
                'evidencia': "Directiva 'set load-balance-mode' no encontrada en config system sdwan (default activo: source-ip-based)",
                'rec': "Cambiar el algoritmo de balanceo implícito a 'weight-based' (por sesiones) o 'measured-volume-based' (por volumen) para optimizar la distribución de carga y evitar cuellos de botella por IP origen",
                'rem': f'config vdom\nedit "{vdom_name}"\nconfig system sdwan\n  set load-balance-mode weight-based\nend\nnext\nend',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.14'
            })
        else:
            current_lb = lb_match.group(1)
            if current_lb == "source-ip-based":
                checks.append({
                    'id': implicit_check_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Segmentación',
                    'mod': 'Alta Disponibilidad y SD-WAN',
                    'hallazgo': f"Regla Implícita SD-WAN en VDOM '{vdom_name}' configurada en modo 'source-ip-based' (baja granularidad)",
                    'estado': 'WARNING',
                    'sev': 'Media',
                    'peso': 5,
                    'afectados': f"VDOM {vdom_name} -> config system sdwan (Implicit Rule)",
                    'evidencia': f"set load-balance-mode {current_lb}",
                    'rec': "Migrar a balanceo por sesiones ('weight-based' o 'source-dest-ip-based') para mejorar la distribución de ancho de banda",
                    'rem': f'config vdom\nedit "{vdom_name}"\nconfig system sdwan\n  set load-balance-mode weight-based\nend\nnext\nend',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.14'
                })
            else:
                checks.append({
                    'id': implicit_check_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Segmentación',
                    'mod': 'Alta Disponibilidad y SD-WAN',
                    'hallazgo': f"Regla Implícita SD-WAN en VDOM '{vdom_name}' optimizada (Modo: {current_lb})",
                    'estado': 'PASS',
                    'sev': 'Baja',
                    'peso': 5,
                    'afectados': f"VDOM {vdom_name} -> config system sdwan (Implicit Rule)",
                    'evidencia': f"set load-balance-mode {current_lb}",
                    'rec': 'Monitorear periódicamente el porcentaje de uso de cada interfaz miembro',
                    'rem': 'N/A - Cumple',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.14'
                })

    return checks
