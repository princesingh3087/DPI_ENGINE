#!/usr/bin/env python3
"""
DPI Engine Analyzer with Geo Location
Usage: python3 analyze.py <input.pcap> [--block-app YouTube] [--block-domain facebook]
"""

import subprocess
import sys
import os
import json
import struct
import socket
import time
import urllib.request
import urllib.error

# ============================================================
# PCAP Parser - IP addresses nikalna
# ============================================================
def extract_ips_from_pcap(pcap_file):
    """PCAP file se unique IP addresses nikalo"""
    ips = set()
    try:
        with open(pcap_file, 'rb') as f:
            # Global header (24 bytes)
            global_hdr = f.read(24)
            if len(global_hdr) < 24:
                return ips

            magic = struct.unpack('<I', global_hdr[:4])[0]
            if magic == 0xa1b2c3d4:
                endian = '<'
            elif magic == 0xd4c3b2a1:
                endian = '>'
            else:
                print(f"[!] Invalid PCAP magic: {hex(magic)}")
                return ips

            while True:
                # Packet header (16 bytes)
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break

                _, _, incl_len, _ = struct.unpack(endian + 'IIII', pkt_hdr)

                # Read packet data
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                # Parse Ethernet (14 bytes) + IP header
                if len(pkt_data) < 34:
                    continue

                eth_type = struct.unpack('>H', pkt_data[12:14])[0]

                # Handle VLAN
                offset = 14
                if eth_type == 0x8100:
                    if len(pkt_data) < 18:
                        continue
                    eth_type = struct.unpack('>H', pkt_data[16:18])[0]
                    offset = 18

                # Only IPv4
                if eth_type != 0x0800:
                    continue

                if len(pkt_data) < offset + 20:
                    continue

                ip_hdr = pkt_data[offset:offset+20]
                src_ip = socket.inet_ntoa(ip_hdr[12:16])
                dst_ip = socket.inet_ntoa(ip_hdr[16:20])

                # Skip private/local IPs
                for ip in [src_ip, dst_ip]:
                    if not (ip.startswith('192.168.') or
                            ip.startswith('10.') or
                            ip.startswith('172.') or
                            ip.startswith('127.') or
                            ip.startswith('0.') or
                            ip == '255.255.255.255'):
                        ips.add(ip)

    except Exception as e:
        print(f"[!] Error reading PCAP: {e}")

    return ips


# ============================================================
# Geo Location Fetcher
# ============================================================
def fetch_geo_locations(ips):
    """ip-api.com se batch geo location fetch karo"""
    geo_data = {}

    if not ips:
        return geo_data

    ip_list = list(ips)
    print(f"\n[Geo] Fetching location for {len(ip_list)} IPs...")

    # Batch API - 100 IPs at a time (free limit)
    batch_size = 100
    for i in range(0, len(ip_list), batch_size):
        batch = ip_list[i:i+batch_size]

        try:
            payload = json.dumps([{"query": ip, "fields": "query,country,countryCode,city,isp,org"} for ip in batch])
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=query,country,countryCode,city,isp,org",
                data=payload.encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )

            with urllib.request.urlopen(req, timeout=10) as resp:
                results = json.loads(resp.read().decode('utf-8'))
                for r in results:
                    if r.get('query'):
                        geo_data[r['query']] = {
                            'country': r.get('country', 'Unknown'),
                            'countryCode': r.get('countryCode', '??'),
                            'city': r.get('city', 'Unknown'),
                            'isp': r.get('isp', 'Unknown'),
                            'org': r.get('org', 'Unknown')
                        }
                print(f"[Geo] ✅ Fetched {len(results)} locations")

            # Rate limit - 1 request per second for batch
            if i + batch_size < len(ip_list):
                time.sleep(1)

        except urllib.error.URLError as e:
            print(f"[Geo] ⚠️  Network error: {e} — skipping geo location")
            break
        except Exception as e:
            print(f"[Geo] ⚠️  Error: {e}")

    return geo_data


# ============================================================
# HTML Report Generator with Geo
# ============================================================
def append_geo_to_report(report_file, geo_data):
    """Existing report.html mein geo location section add karo"""
    if not os.path.exists(report_file):
        print(f"[!] Report file not found: {report_file}")
        return

    if not geo_data:
        print("[Geo] No geo data to add")
        return

    # Country stats
    country_counts = {}
    for ip, info in geo_data.items():
        country = f"{info.get('countryCode','??')} {info.get('country','Unknown')}"
        country_counts[country] = country_counts.get(country, 0) + 1

    sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)

    # Build geo table HTML
    rows_html = ""
    for ip, info in sorted(geo_data.items()):
        flag = info.get('countryCode', '??')
        country = info.get('country', 'Unknown')
        city = info.get('city', 'Unknown')
        org = info.get('org', info.get('isp', 'Unknown'))
        rows_html += f"""
        <tr>
          <td style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#22d3ee">{ip}</td>
          <td><span style="font-size:1rem">{get_flag_emoji(flag)}</span> {country}</td>
          <td style="color:#94a3b8">{city}</td>
          <td style="color:#64748b;font-size:0.75rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{org}</td>
        </tr>"""

    # Country chart data
    chart_labels = ", ".join([f'"{c[0]}"' for c in sorted_countries[:10]])
    chart_data = ", ".join([str(c[1]) for c in sorted_countries[:10]])
    chart_colors = '["#6366f1","#22d3ee","#f59e0b","#10b981","#ef4444","#8b5cf6","#ec4899","#14b8a6","#f97316","#84cc16"]'

    geo_section = f"""
<!-- GEO LOCATION SECTION -->
<div class="card" style="margin-bottom:1.5rem">
  <h2>&#127757; Geo Location — IP Traffic Origins</h2>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:1.5rem">
    <div>
      <div style="font-size:0.75rem;color:#64748b;margin-bottom:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.08em">Top Countries</div>
      <div style="position:relative;height:200px"><canvas id="geoChart"></canvas></div>
    </div>
    <div>
      <div style="font-size:0.75rem;color:#64748b;margin-bottom:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.08em">Country Breakdown</div>
      {"".join([f'<div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.4rem"><span style="font-size:0.9rem">{get_flag_emoji(c[0][:2])}</span><span style="font-size:0.8rem;flex:1">{c[0][3:]}</span><span style="font-size:0.75rem;font-family:JetBrains Mono,monospace;color:#22d3ee">{c[1]} IPs</span></div>' for c in sorted_countries[:8]])}
    </div>
  </div>
  <div style="font-size:0.75rem;color:#64748b;margin-bottom:0.75rem;font-weight:600;text-transform:uppercase;letter-spacing:0.08em">IP Details ({len(geo_data)} addresses)</div>
  <div style="max-height:300px;overflow-y:auto;border-radius:8px;border:1px solid #1e2d45">
    <table style="width:100%;border-collapse:collapse">
      <thead>
        <tr style="background:#1a2235;position:sticky;top:0">
          <th style="text-align:left;padding:0.6rem 0.75rem;font-size:0.7rem;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:0.08em">IP Address</th>
          <th style="text-align:left;padding:0.6rem 0.75rem;font-size:0.7rem;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:0.08em">Country</th>
          <th style="text-align:left;padding:0.6rem 0.75rem;font-size:0.7rem;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:0.08em">City</th>
          <th style="text-align:left;padding:0.6rem 0.75rem;font-size:0.7rem;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:0.08em">Organization</th>
        </tr>
      </thead>
      <tbody style="font-size:0.8rem">
        {rows_html}
      </tbody>
    </table>
  </div>
</div>

<script>
new Chart(document.getElementById('geoChart').getContext('2d'), {{
  type: 'bar',
  data: {{
    labels: [{chart_labels}],
    datasets: [{{
      data: [{chart_data}],
      backgroundColor: {chart_colors},
      borderRadius: 6,
      borderSkipped: false
    }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }}, tooltip: {{ backgroundColor: '#1a2235', borderColor: '#1e2d45', borderWidth: 1, titleColor: '#e2e8f0', bodyColor: '#94a3b8' }} }},
    scales: {{
      x: {{ grid: {{ color: '#1e2d45' }}, ticks: {{ color: '#64748b', font: {{ size: 10 }} }} }},
      y: {{ grid: {{ color: '#1e2d45' }}, ticks: {{ color: '#64748b', font: {{ size: 10 }} }}, title: {{ display: true, text: 'IPs', color: '#64748b' }} }}
    }}
  }}
}});
</script>
"""

    # Insert geo section before footer
    with open(report_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Insert before footer div
    content = content.replace(
        '<div class="footer">',
        geo_section + '\n<div class="footer">'
    )

    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"[Geo] ✅ Geo location added to report!")


def get_flag_emoji(country_code):
    """Country code se flag emoji banao"""
    if not country_code or len(country_code) != 2:
        return "🌐"
    try:
        return chr(0x1F1E6 + ord(country_code[0].upper()) - ord('A')) + \
               chr(0x1F1E6 + ord(country_code[1].upper()) - ord('A'))
    except:
        return "🌐"


# ============================================================
# Main
# ============================================================
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze.py <input.pcap> [dpi options]")
        print("Example: python3 analyze.py capture.pcap --block-app YouTube")
        sys.exit(1)

    pcap_file = sys.argv[1]
    extra_args = sys.argv[2:]

    if not os.path.exists(pcap_file):
        print(f"[!] File not found: {pcap_file}")
        sys.exit(1)

    # Step 1: Extract IPs
    print(f"\n[*] Extracting IPs from {pcap_file}...")
    ips = extract_ips_from_pcap(pcap_file)
    print(f"[*] Found {len(ips)} unique public IPs")

    # Step 2: Fetch geo locations
    geo_data = fetch_geo_locations(ips)

    # Step 3: Run DPI engine
    print(f"\n[*] Running DPI Engine...")
    cmd = ["./dpi_engine.exe", pcap_file, "output.pcap"] + extra_args
    result = subprocess.run(cmd)

    if result.returncode != 0:
        print("[!] DPI Engine failed!")
        sys.exit(1)

    # Step 4: Add geo to report
    print(f"\n[*] Adding geo location to report...")
    append_geo_to_report("report.html", geo_data)

    print(f"\n✅ Done! Open report.html in browser.")
    print(f"   Found {len(geo_data)} IPs from {len(set(v['country'] for v in geo_data.values()))} countries!")


if __name__ == "__main__":
    main()
