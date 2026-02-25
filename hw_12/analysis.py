"""
DHCP Network Dump Forensics Analysis — Alternative Visualisation
=================================================================
Three chart types not used in the first version:
  1. Bubble timeline   — each packet as a bubble (size = bytes, x = frame, y = direction)
  2. DHCP option heatmap — which options appear in which packets
  3. Network-graph view — client / server nodes with curved-arc packet flows
"""

import json
import csv
from datetime import datetime
from pathlib import Path

import pyshark
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyArrowPatch
import matplotlib.patheffects as pe
import seaborn as sns
import numpy as np

# ── paths ────────────────────────────────────────────────────────────────────
DIR      = Path(__file__).parent
PCAP     = DIR / "dhcp.pcapng"
OUT_CSV  = DIR / "dhcp_artifacts.csv"
OUT_JSON = DIR / "dhcp_artifacts.json"
OUT_PLOT = DIR / "dhcp_visualization.png"

DHCP_TYPES = {
    "1": "Discover", "2": "Offer", "3": "Request",
    "4": "Decline",  "5": "ACK",   "6": "NAK",
    "7": "Release",  "8": "Inform",
}

TYPE_COLORS = {
    "Discover": "#4C72B0",
    "Offer":    "#55A868",
    "Request":  "#DD8452",
    "ACK":      "#8172B2",
}

# ── Stage 1: Load ─────────────────────────────────────────────────────────────
print("Этап 1 — загрузка дампа …")
cap     = pyshark.FileCapture(str(PCAP))
packets = list(cap)
cap.close()
print(f"  {len(packets)} пакетов\n")

# ── Stage 2: Extract artifacts ────────────────────────────────────────────────
print("Этап 2 — извлечение артефактов …")

def safe(layer, field, default="N/A"):
    try:
        return str(getattr(layer, field))
    except AttributeError:
        return default

artifacts = []
for pkt in packets:
    if not hasattr(pkt, "dhcp"):
        continue
    dhcp = pkt.dhcp
    ip   = pkt.ip  if hasattr(pkt, "ip")  else None
    eth  = pkt.eth if hasattr(pkt, "eth") else None

    msg_code = safe(dhcp, "option_dhcp")
    record = {
        "frame":          int(pkt.number),
        "timestamp":      str(pkt.sniff_time),
        "size_bytes":     int(pkt.length),
        "dhcp_type":      DHCP_TYPES.get(msg_code, f"Type-{msg_code}"),
        "src_ip":         safe(ip,  "src")         if ip  else "N/A",
        "dst_ip":         safe(ip,  "dst")         if ip  else "N/A",
        "src_mac":        safe(eth, "src")         if eth else "N/A",
        "dst_mac":        safe(eth, "dst")         if eth else "N/A",
        "client_mac":     safe(dhcp, "hw_mac_addr"),
        "client_ip":      safe(dhcp, "ip_client"),
        "offered_ip":     safe(dhcp, "ip_your"),
        "server_id":      safe(dhcp, "option_dhcp_server_id"),
        "subnet_mask":    safe(dhcp, "option_subnet_mask"),
        "lease_time_s":   safe(dhcp, "option_ip_address_lease_time"),
        "renewal_s":      safe(dhcp, "option_renewal_time_value"),
        "rebind_s":       safe(dhcp, "option_rebinding_time_value"),
        "req_ip":         safe(dhcp, "option_requested_ip_address"),
        "transaction_id": safe(dhcp, "id"),
        # boolean option presence flags (for heatmap)
        "opt_msg_type":   True,
        "opt_client_id":  safe(dhcp, "option_requested_ip_address") != "N/A"
                          or safe(dhcp, "hw_mac_addr") != "N/A",
        "opt_req_ip":     safe(dhcp, "option_requested_ip_address") not in ("N/A", "0.0.0.0"),
        "opt_server_id":  safe(dhcp, "option_dhcp_server_id") != "N/A",
        "opt_subnet":     safe(dhcp, "option_subnet_mask") != "N/A",
        "opt_lease":      safe(dhcp, "option_ip_address_lease_time") != "N/A",
        "opt_renewal":    safe(dhcp, "option_renewal_time_value") != "N/A",
        "opt_rebind":     safe(dhcp, "option_rebinding_time_value") != "N/A",
        "opt_param_req":  safe(dhcp, "option_request_list_item") != "N/A",
    }
    artifacts.append(record)
    print(f"  Frame {record['frame']} | {record['dhcp_type']:<10} | "
          f"{record['size_bytes']} B | {record['src_ip']} → {record['dst_ip']}")

# save
with open(OUT_CSV, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=artifacts[0].keys())
    writer.writeheader()
    writer.writerows(artifacts)
with open(OUT_JSON, "w") as f:
    json.dump(artifacts, f, indent=2, default=str)
print(f"\n  → {OUT_CSV.name}  /  {OUT_JSON.name}\n")

# ── Stage 3: Visualisation ────────────────────────────────────────────────────
print("Этап 3 — построение визуализации …")

sns.set_theme(style="dark", palette="muted")
fig = plt.figure(figsize=(16, 11), facecolor="#1a1a2e")
fig.suptitle(
    "DHCP сетевой дамп — Форензика",
    fontsize=16, fontweight="bold", color="white", y=0.98,
)

DARK_BG = "#1a1a2e"
PANEL_BG = "#16213e"

def styled_ax(ax):
    ax.set_facecolor(PANEL_BG)
    for spine in ax.spines.values():
        spine.set_edgecolor("#334")
    ax.tick_params(colors="#aab")
    ax.xaxis.label.set_color("#aab")
    ax.yaxis.label.set_color("#aab")
    ax.title.set_color("white")
    return ax

# ────────────────────────────────────────────────────────────────────────────
# Plot 1 (top, full width): Bubble timeline
# x = frame number, y = "lane" (0=client-sent, 1=server-sent)
# bubble size ∝ packet size, color = message type
# ────────────────────────────────────────────────────────────────────────────
ax1 = styled_ax(fig.add_subplot(3, 2, (1, 2)))

t0_dt = datetime.fromisoformat(artifacts[0]["timestamp"])
times    = [(datetime.fromisoformat(r["timestamp"]) - t0_dt).total_seconds() * 1000
            for r in artifacts]
lanes    = [0.3 if r["dhcp_type"] in ("Discover", "Request") else 0.7
            for r in artifacts]
sizes    = [r["size_bytes"] * 2.2 for r in artifacts]
colors_b = [TYPE_COLORS[r["dhcp_type"]] for r in artifacts]

sc = ax1.scatter(times, lanes, s=sizes, c=colors_b, alpha=0.85,
                 edgecolors="white", linewidths=0.8, zorder=3)

# horizontal band labels
ax1.axhspan(0.05, 0.5,  alpha=0.07, color="#4C72B0")
ax1.axhspan(0.5,  0.95, alpha=0.07, color="#55A868")
ax1.text(-0.5, 0.3,  "Клиент\n(отправил)", ha="right", va="center",
         fontsize=9, color="#4C72B0aa")
ax1.text(-0.5, 0.7, "Сервер\n(отправил)", ha="right", va="center",
         fontsize=9, color="#55A868aa")

# vertical dashed connectors (Discover↔Offer, Request↔ACK)
for i in range(0, len(artifacts) - 1, 2):
    x0, y0 = times[i],   lanes[i]
    x1, y1 = times[i+1], lanes[i+1]
    ax1.plot([x0, x1], [y0, y1], "--", color="#ffffff33", lw=1.2, zorder=1)

for t, lane, r in zip(times, lanes, artifacts):
    offset = -0.09 if lane < 0.5 else 0.09
    ax1.text(t, lane + offset, r["dhcp_type"],
             ha="center", va="center", fontsize=9, fontweight="bold",
             color=TYPE_COLORS[r["dhcp_type"]])
    ax1.text(t, lane + offset * 2.1, f"{r['size_bytes']} B",
             ha="center", va="center", fontsize=7.5, color="#99a")

legend_patches = [mpatches.Patch(color=v, label=k) for k, v in TYPE_COLORS.items()]
ax1.legend(handles=legend_patches, loc="upper right",
           framealpha=0.3, facecolor="#334", edgecolor="#556",
           labelcolor="white", fontsize=8)

ax1.set_xlim(-2, max(times) + 3)
ax1.set_ylim(0.0, 1.0)
ax1.set_yticks([])
ax1.set_xlabel("Смещение времени (мс)", fontsize=10)
ax1.set_title("Хронология пузырьков  (размер пузырька = байты пакета)", fontsize=11)

# ────────────────────────────────────────────────────────────────────────────
# Plot 2 (bottom-left): DHCP option presence heatmap
# ────────────────────────────────────────────────────────────────────────────
ax2 = styled_ax(fig.add_subplot(3, 2, (3, 5)))

option_cols = [
    ("opt_msg_type",  "Тип сообщ."),
    ("opt_client_id", "Client ID"),
    ("opt_req_ip",    "Запрош. IP"),
    ("opt_server_id", "Server ID"),
    ("opt_subnet",    "Маска подсети"),
    ("opt_lease",     "Время аренды"),
    ("opt_renewal",   "Обновление"),
    ("opt_rebind",    "Перепривязка"),
    ("opt_param_req", "Список параметров"),
]

row_labels = [f"Кадр {r['frame']}\n({r['dhcp_type']})" for r in artifacts]
col_labels = [c[1] for c in option_cols]
matrix     = np.array([[int(r[c[0]]) for c in option_cols] for r in artifacts],
                      dtype=float)

cmap = sns.color_palette(
    ["#1a1a2e", "#4C72B0", "#55A868", "#DD8452", "#8172B2"],
    as_cmap=False
)
# Build a two-tone colormap: 0 = dark, 1 = colored per row
# Use a different accent per row
row_colors = [TYPE_COLORS[r["dhcp_type"]] for r in artifacts]

for row_idx, row in enumerate(matrix):
    for col_idx, val in enumerate(row):
        face = row_colors[row_idx] if val else "#1e1e3a"
        rect = plt.Rectangle(
            (col_idx - 0.5, row_idx - 0.5), 1, 1,
            facecolor=face, alpha=0.85 if val else 0.4,
            edgecolor="#334", linewidth=0.8
        )
        ax2.add_patch(rect)
        sym = "✓" if val else "·"
        ax2.text(col_idx, row_idx, sym,
                 ha="center", va="center",
                 fontsize=14 if val else 10,
                 color="white" if val else "#445",
                 fontweight="bold" if val else "normal")

ax2.set_xlim(-0.5, len(col_labels) - 0.5)
ax2.set_ylim(-0.5, len(row_labels) - 0.5)
ax2.set_xticks(range(len(col_labels)))
ax2.set_xticklabels(col_labels, rotation=35, ha="right", fontsize=8.5, color="#ccd")
ax2.set_yticks(range(len(row_labels)))
ax2.set_yticklabels(row_labels, fontsize=9, color="#ccd")
ax2.set_title("Тепловая карта наличия DHCP-опций", fontsize=11)
ax2.invert_yaxis()

# ────────────────────────────────────────────────────────────────────────────
# Plot 3 (bottom-right): Network graph
# Client node (left) ↔ Server node (right), curved arcs per packet
# ────────────────────────────────────────────────────────────────────────────
ax3 = styled_ax(fig.add_subplot(3, 2, (4, 6)))
ax3.set_xlim(0, 10)
ax3.set_ylim(0, 10)
ax3.set_aspect("equal")
ax3.axis("off")
ax3.set_title("Граф сети  (дуги = поток пакетов, подпись = тип)", fontsize=11)

# Node positions
CLIENT_POS = (2.0, 5.0)
SERVER_POS = (8.0, 5.0)
NODE_R     = 0.9

# Draw nodes
for pos, label, sub, color in [
    (CLIENT_POS, "КЛИЕНТ",  "00:0b:82\n:01:fc:42", "#4C72B0"),
    (SERVER_POS, "СЕРВЕР",  "192.168.0.1",          "#55A868"),
]:
    circle = plt.Circle(pos, NODE_R, color=color, alpha=0.25, zorder=2)
    border = plt.Circle(pos, NODE_R, fill=False, edgecolor=color, lw=2, zorder=3)
    ax3.add_patch(circle)
    ax3.add_patch(border)
    ax3.text(pos[0], pos[1] + 0.15, label, ha="center", va="center",
             fontsize=10, fontweight="bold", color="white", zorder=4)
    ax3.text(pos[0], pos[1] - 0.3, sub, ha="center", va="center",
             fontsize=7, color=color, zorder=4)

# Draw arcs: Discover and Request go client→server; Offer and ACK go server→client
# Use different vertical offsets so arcs don't overlap
arc_params = [
    # (type, x_start, x_end, curvature, y_offset_label)
    ("Discover", CLIENT_POS, SERVER_POS,  0.4,  7.5),
    ("Offer",    SERVER_POS, CLIENT_POS, -0.4,  6.2),
    ("Request",  CLIENT_POS, SERVER_POS,  0.25, 4.0),
    ("ACK",      SERVER_POS, CLIENT_POS, -0.25, 2.8),
]

for (dtype, p_src, p_dst, rad, y_lbl), art in zip(arc_params, artifacts):
    color = TYPE_COLORS[dtype]
    # Draw FancyArrowPatch with arc connectionstyle
    start = (p_src[0] + NODE_R * (1 if p_src[0] < 5 else -1), p_src[1])
    end   = (p_dst[0] + NODE_R * (1 if p_dst[0] < 5 else -1), p_dst[1])
    arrow = FancyArrowPatch(
        start, end,
        connectionstyle=f"arc3,rad={rad}",
        arrowstyle="-|>",
        mutation_scale=16,
        color=color,
        lw=2.2,
        alpha=0.9,
        zorder=3,
    )
    ax3.add_patch(arrow)

    # Label at midpoint of arc
    mid_x = (start[0] + end[0]) / 2
    mid_y = y_lbl
    box = dict(boxstyle="round,pad=0.3", facecolor=PANEL_BG,
               edgecolor=color, linewidth=1.2, alpha=0.9)
    ax3.text(mid_x, mid_y, f"{dtype}\n{art['size_bytes']} B",
             ha="center", va="center", fontsize=8.5,
             color=color, fontweight="bold", bbox=box, zorder=5)

# Transaction ID annotations
for tx_id, x_pos in [("TXN 0x3d1d", 5.0), ("TXN 0x3d1e", 5.0)]:
    pass  # skip to keep graph clean

ax3.text(5.0, 9.5, "Транзакция 0x3d1d", ha="center", fontsize=8,
         color=TYPE_COLORS["Discover"], alpha=0.7,
         bbox=dict(boxstyle="round", facecolor="#1a1a2e", edgecolor="#334", alpha=0.6))
ax3.text(5.0, 0.5, "Транзакция 0x3d1e", ha="center", fontsize=8,
         color=TYPE_COLORS["Request"], alpha=0.7,
         bbox=dict(boxstyle="round", facecolor="#1a1a2e", edgecolor="#334", alpha=0.6))

plt.tight_layout(rect=[0, 0, 1, 0.97])
plt.savefig(OUT_PLOT, dpi=150, bbox_inches="tight", facecolor=DARK_BG)
print(f"  → {OUT_PLOT.name}")
print("Готово.")
