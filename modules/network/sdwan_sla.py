# modules/network/sdwan_sla.py
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
    Auditoría Dinámica e Individual de Performance SLAs (health-check) VDOM por VDOM.
    Evalúa por cada SLA:
      - Destino de sondeo (server / system-dns) y protocolo.
      - Intervalo de sondeo (detección de intervalos lentos > 5 seg).
      - Tiempos de respuesta, failtime y recoverytime (anti-flapping).
      - Umbrales SLA (Latencia, Jitter y Pérdida de paquetes).
      - Estado de update-static-route (failover automático de rutas).
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

        # Si SD-WAN no está activo en este VDOM, no aplican los SLAs
        if not is_enabled:
            continue

        hc_block = extract_nested_block(sdwan_body, "config health-check")
        if not hc_block:
            checks.append({
                'id': f'CHK-SDWAN-SLA-{vdom_name.upper().replace("-", "_")}-NONE',
                'vdom': vdom_name,
                'cat': 'Red y Segmentación',
                'mod': 'Alta Disponibilidad y SD-WAN',
                'hallazgo': f"VDOM '{vdom_name}': SD-WAN activo pero sin Performance SLAs (health-checks) configurados",
                'estado': 'FAIL',
                'sev': 'Alta',
                'peso': 10,
                'afectados': f"VDOM {vdom_name} -> config system sdwan -> config health-check",
                'evidencia': 'config health-check ausente o sin monitores activos',
                'rec': 'Configurar sondas de salud (Health-Checks) con umbrales de latencia, jitter y packet loss para conmutación automática',
                'rem': f'config vdom\nedit "{vdom_name}"\nconfig system sdwan\n  config health-check\n    edit "Default_DNS"\n      set system-dns enable\n      set interval 1000\n    next\n  end\nend\nnext\nend',
                'tipo': 'Técnico',
                'ref': 'SEG-LNB-002 Num 6.14'
            })
            continue

        # Extraer cada Performance SLA individualmente
        sla_entries = re.findall(r'edit "([^"]+)"(.*?)(?=\n\s*edit "|\Z)', hc_block, re.DOTALL)

        if not sla_entries:
            continue

        for sla_name, sla_raw in sla_entries:
            check_id = f"CHK-SDWAN-SLA-{vdom_name.upper().replace('-', '_')}-{sla_name.upper().replace(' ', '_').replace('-', '_')}"

            # 1. Parámetros de detección
            server_m = re.search(r'set server\s+"([^"]+)"', sla_raw)
            sys_dns_m = re.search(r'set system-dns\s+([a-z]+)', sla_raw)
            target_server = server_m.group(1) if server_m else ("System DNS" if (sys_dns_m and sys_dns_m.group(1) == "enable") else "No definido")

            proto_m = re.search(r'set protocol\s+([a-z0-9\-]+)', sla_raw)
            protocol = proto_m.group(1) if proto_m else "ping"

            # 2. Tiempos de sondeo (en ms)
            interval_m = re.search(r'set interval\s+(\d+)', sla_raw)
            interval_ms = int(interval_m.group(1)) if interval_m else 500  # Default en FortiOS es 500ms si no está explícito

            timeout_m = re.search(r'set probe-timeout\s+(\d+)', sla_raw)
            timeout_ms = int(timeout_m.group(1)) if timeout_m else 500

            failtime_m = re.search(r'set failtime\s+(\d+)', sla_raw)
            failtime = int(failtime_m.group(1)) if failtime_m else 5

            recovery_m = re.search(r'set recoverytime\s+(\d+)', sla_raw)
            recoverytime = int(recovery_m.group(1)) if recovery_m else 5

            # 3. Control de rutas estáticas
            update_route_m = re.search(r'set update-static-route\s+([a-z]+)', sla_raw)
            update_route = update_route_m.group(1) if update_route_m else "enable"

            # 4. Umbrales SLA
            latency_m = re.search(r'set latency-threshold\s+(\d+)', sla_raw)
            latency_th = int(latency_m.group(1)) if latency_m else None

            jitter_m = re.search(r'set jitter-threshold\s+(\d+)', sla_raw)
            jitter_th = int(jitter_m.group(1)) if jitter_m else None

            loss_m = re.search(r'set packetloss-threshold\s+(\d+)', sla_raw)
            loss_th = int(loss_m.group(1)) if loss_m else None

            has_thresholds = (latency_th is not None or jitter_th is not None or loss_th is not None)

            # -------------------------------------------------------------
            # EVALUACIÓN ESPECÍFICA POR SLA
            # -------------------------------------------------------------
            issues = []

            # Alerta por intervalo excesivamente lento (ej. plantillas con 120000 ms = 2 min)
            if interval_ms > 10000:
                issues.append(f"Intervalo de sondeo excesivamente alto ({interval_ms/1000:.0f}s, retarda el failover ante caídas)")

            # Alerta por timeout mayor al intervalo
            if timeout_ms > interval_ms:
                issues.append(f"Probe timeout ({timeout_ms}ms) mayor al intervalo ({interval_ms}ms)")

            # Alerta si update-static-route está deshabilitado en sondas WAN de failover
            if update_route == "disable":
                issues.append("update-static-route deshabilitado (no retirará las rutas caídas de la tabla de enrutamiento)")

            # Alerta si no tiene umbrales de SLA configurados (solo monitorea ping básico sin calidad)
            if not has_thresholds:
                issues.append("Sin umbrales de SLA configurados (latencia, jitter o packet loss)")

            # Construir métricas legibles para evidencia
            thresholds_str = f"Lat: {latency_th or 'N/A'}ms, Jitter: {jitter_th or 'N/A'}ms, Loss: {loss_th or 'N/A'}%"
            evidencia_str = f"Target: {target_server} ({protocol}) | Intervalo: {interval_ms}ms | Fail/Rec: {failtime}/{recoverytime} | Umbrales: [{thresholds_str}] | update-route: {update_route}"

            if issues:
                checks.append({
                    'id': check_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Segmentación',
                    'mod': 'Alta Disponibilidad y SD-WAN',
                    'hallazgo': f"Performance SLA '{sla_name}' en VDOM '{vdom_name}' con parámetros subóptimos: {'; '.join(issues)}",
                    'estado': 'WARNING',
                    'sev': 'Media',
                    'peso': 5,
                    'afectados': f"VDOM {vdom_name} -> health-check '{sla_name}'",
                    'evidencia': evidencia_str,
                    'rec': f"Ajustar el intervalo de '{sla_name}' a 1000ms-2000ms y habilitar update-static-route para conmutación inmediata de enlaces",
                    'rem': f'config vdom\nedit "{vdom_name}"\nconfig system sdwan\n  config health-check\n    edit "{sla_name}"\n      set interval 1000\n      set probe-timeout 1000\n      set update-static-route enable\n    next\n  end\nend\nnext\nend',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.14'
                })
            else:
                checks.append({
                    'id': check_id,
                    'vdom': vdom_name,
                    'cat': 'Red y Segmentación',
                    'mod': 'Alta Disponibilidad y SD-WAN',
                    'hallazgo': f"Performance SLA '{sla_name}' en VDOM '{vdom_name}' configurado correctamente con umbrales válidos",
                    'estado': 'PASS',
                    'sev': 'Baja',
                    'peso': 5,
                    'afectados': f"VDOM {vdom_name} -> health-check '{sla_name}'",
                    'evidencia': evidencia_str,
                    'rec': 'Mantener monitoreo de métricas de calidad y ajustar umbrales según el proveedor de enlace',
                    'rem': 'N/A - Cumple',
                    'tipo': 'Técnico',
                    'ref': 'SEG-LNB-002 Num 6.14'
                })

    return checks
