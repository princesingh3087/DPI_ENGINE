#pragma once
#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <map>
#include "types.h"

namespace DPI {

class ReportGenerator {
public:
    struct TimelinePoint {
        uint32_t second;
        std::unordered_map<AppType, uint64_t> app_counts;
    };

    struct ReportData {
        uint64_t total_packets=0, total_bytes=0, tcp_packets=0, udp_packets=0, forwarded=0, dropped=0;
        std::unordered_map<AppType, uint64_t> app_counts;
        std::unordered_map<std::string, AppType> detected_snis;
        std::string input_file;
        std::vector<std::string> blocked_rules;
        std::map<uint32_t, std::unordered_map<AppType, uint64_t>> timeline; // second -> app -> count
        std::vector<std::pair<std::string, uint64_t>> top_talkers; // domain -> packet count, sorted
    };

    static bool generate(const std::string& output_path, const ReportData& data) {
        std::ofstream f(output_path);
        if (!f.is_open()) return false;

        time_t now = time(nullptr);
        char time_buf[64];
        strftime(time_buf, sizeof(time_buf), "%B %d, %Y at %H:%M:%S", localtime(&now));

        // Sort apps by count
        std::vector<std::pair<AppType, uint64_t>> sorted_apps(
            data.app_counts.begin(), data.app_counts.end());
        std::sort(sorted_apps.begin(), sorted_apps.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });

        // Pie chart data
        std::string chart_labels, chart_data, chart_colors;
        std::vector<std::string> colors = {
            "#6366f1","#22d3ee","#f59e0b","#10b981",
            "#ef4444","#8b5cf6","#ec4899","#14b8a6",
            "#f97316","#84cc16","#06b6d4","#a855f7"
        };
        int ci = 0;
        for (const auto& [app, count] : sorted_apps) {
            if (ci > 0) { chart_labels += ","; chart_data += ","; chart_colors += ","; }
            chart_labels += "\"" + appTypeToString(app) + "\"";
            chart_data += std::to_string(count);
            chart_colors += "\"" + colors[ci % colors.size()] + "\"";
            ci++;
        }

        // Timeline data - build per-app datasets
        // Find top 6 apps for timeline
        std::vector<AppType> top_apps;
        for (int i = 0; i < (int)sorted_apps.size() && i < 6; i++) {
            if (sorted_apps[i].first != AppType::UNKNOWN &&
                sorted_apps[i].first != AppType::HTTPS &&
                sorted_apps[i].first != AppType::DNS) {
                top_apps.push_back(sorted_apps[i].first);
            }
        }
        // If less than 3, add HTTPS and DNS
        if (top_apps.size() < 3) {
            for (const auto& [app, count] : sorted_apps) {
                if (top_apps.size() >= 6) break;
                if (std::find(top_apps.begin(), top_apps.end(), app) == top_apps.end()) {
                    top_apps.push_back(app);
                }
            }
        }

        // Build timeline labels (seconds relative to start)
        std::string timeline_labels;
        std::unordered_map<AppType, std::string> timeline_datasets;

        if (!data.timeline.empty()) {
            uint32_t start_sec = data.timeline.begin()->first;
            uint32_t end_sec = data.timeline.rbegin()->first;

            for (uint32_t s = start_sec; s <= end_sec; s++) {
                if (!timeline_labels.empty()) timeline_labels += ",";
                timeline_labels += "\"" + std::to_string(s - start_sec) + "s\"";
            }

            for (auto app : top_apps) {
                std::string pts;
                for (uint32_t s = start_sec; s <= end_sec; s++) {
                    if (!pts.empty()) pts += ",";
                    auto it = data.timeline.find(s);
                    if (it != data.timeline.end()) {
                        auto ait = it->second.find(app);
                        pts += (ait != it->second.end()) ? std::to_string(ait->second) : "0";
                    } else {
                        pts += "0";
                    }
                }
                timeline_datasets[app] = pts;
            }
        }

        // Build timeline datasets JS
        std::string timeline_ds_js;
        int tci = 0;
        for (auto app : top_apps) {
            if (!timeline_ds_js.empty()) timeline_ds_js += ",\n";
            std::string color = colors[tci % colors.size()];
            timeline_ds_js += "{\n";
            timeline_ds_js += "  label: \"" + appTypeToString(app) + "\",\n";
            timeline_ds_js += "  data: [" + timeline_datasets[app] + "],\n";
            timeline_ds_js += "  borderColor: \"" + color + "\",\n";
            timeline_ds_js += "  backgroundColor: \"" + color + "18\",\n";
            timeline_ds_js += "  borderWidth: 2,\n";
            timeline_ds_js += "  pointRadius: 2,\n";
            timeline_ds_js += "  tension: 0.4,\n";
            timeline_ds_js += "  fill: true\n";
            timeline_ds_js += "}";
            tci++;
        }

        auto fmtBytes = [](uint64_t b) -> std::string {
            std::ostringstream ss;
            if (b > 1024*1024) ss << std::fixed << std::setprecision(1) << (b/1024.0/1024.0) << " MB";
            else if (b > 1024) ss << std::fixed << std::setprecision(1) << (b/1024.0) << " KB";
            else ss << b << " B";
            return ss.str();
        };

        double drop_pct = data.total_packets > 0 ? (100.0 * data.dropped / data.total_packets) : 0;

        // Write HTML
        f << "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n";
        f << "<title>DPI Engine Report</title>\n";
        f << "<script src=\"https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js\"></script>\n";
        f << "<style>\n";
        f << "@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;500;600;700&display=swap');\n";
        f << ":root{--bg:#0a0e1a;--surface:#111827;--surface2:#1a2235;--border:#1e2d45;--accent:#6366f1;--accent2:#22d3ee;--text:#e2e8f0;--muted:#64748b;--success:#10b981;--danger:#ef4444;--warn:#f59e0b;}\n";
        f << "body.light{--bg:#f1f5f9;--surface:#ffffff;--surface2:#f8fafc;--border:#e2e8f0;--text:#0f172a;--muted:#64748b;}\n";
        f << ".sw{position:relative;width:38px;height:20px;}.sw input{opacity:0;width:0;height:0;}.sl{position:absolute;inset:0;background:#334155;border-radius:20px;transition:.3s;cursor:pointer;}.sl:before{content:'';position:absolute;height:14px;width:14px;left:3px;bottom:3px;background:white;border-radius:50%;transition:.3s;}input:checked+.sl{background:#6366f1;}input:checked+.sl:before{transform:translateX(18px);}.tl{font-size:0.72rem;color:var(--muted);font-weight:500;min-width:60px;}\n";
        f << ".topbar{position:fixed;top:1rem;left:0;right:0;display:flex;align-items:center;justify-content:center;z-index:999;pointer-events:none;}.topbar-inner{display:flex;align-items:center;gap:0.75rem;background:var(--surface);border:1px solid var(--border);border-radius:50px;padding:0.35rem 0.5rem 0.35rem 1rem;box-shadow:0 4px 16px rgba(0,0,0,0.25);pointer-events:auto;}.topbar-divider{width:1px;height:20px;background:var(--border);}.export-group{display:flex;gap:0.35rem;}.export-btn{display:flex;align-items:center;gap:0.4rem;background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:0.4rem 0.85rem;font-size:0.72rem;font-weight:500;color:var(--text);cursor:pointer;font-family:Inter,sans-serif;transition:all 0.2s;white-space:nowrap;}.export-btn:hover{border-color:var(--accent);color:var(--accent);background:var(--accent)15;}.export-btn .icon{font-size:0.85rem;}.domain-controls{display:flex;gap:0.6rem;margin-bottom:1rem;flex-wrap:wrap;align-items:center;}.search-box{flex:1;min-width:180px;position:relative;}.search-box input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:0.5rem 0.75rem 0.5rem 2rem;font-size:0.8rem;color:var(--text);font-family:Inter,sans-serif;outline:none;transition:border-color 0.2s;}.search-box input:focus{border-color:var(--accent);}.search-box .icon{position:absolute;left:0.6rem;top:50%;transform:translateY(-50%);color:var(--muted);font-size:0.8rem;pointer-events:none;}.filter-group{display:flex;gap:0.35rem;}.filter-btn{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:0.5rem 0.9rem;font-size:0.75rem;font-weight:500;color:var(--muted);cursor:pointer;font-family:Inter,sans-serif;transition:all 0.2s;}.filter-btn:hover{color:var(--text);border-color:var(--accent);}.filter-btn.active{background:var(--accent);color:#fff;border-color:var(--accent);}.domain-item.hidden{display:none;}.no-results{text-align:center;padding:2rem;color:var(--muted);font-size:0.85rem;display:none;}.talker-row{display:flex;align-items:center;gap:0.75rem;padding:0.5rem 0;border-bottom:1px solid var(--border);}.talker-row:last-child{border-bottom:none;}.talker-rank{width:24px;height:24px;border-radius:50%;background:var(--surface2);display:flex;align-items:center;justify-content:center;font-size:0.7rem;font-weight:700;color:var(--muted);flex-shrink:0;}.talker-rank.top1{background:#f59e0b;color:#000;}.talker-rank.top2{background:#94a3b8;color:#000;}.talker-rank.top3{background:#b45309;color:#fff;}.talker-name{font-size:0.8rem;font-family:JetBrains Mono,monospace;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}.talker-bar-wrap{flex:2;background:var(--surface2);border-radius:4px;height:8px;overflow:hidden;}.talker-bar{height:100%;border-radius:4px;background:linear-gradient(90deg,var(--accent),var(--accent2));}.talker-count{font-size:0.75rem;color:var(--muted);font-family:JetBrains Mono,monospace;min-width:70px;text-align:right;}\n";
        f << "*{margin:0;padding:0;box-sizing:border-box;}\n";
        f << "body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;min-height:100vh;padding:2rem;transition:background 0.3s,color 0.3s;}\n";
        f << ".header{display:flex;align-items:center;justify-content:space-between;margin-bottom:2.5rem;padding-bottom:1.5rem;border-bottom:1px solid var(--border);}\n";
        f << ".logo{display:flex;align-items:center;gap:0.75rem;}\n";
        f << ".logo-icon{width:42px;height:42px;display:flex;align-items:center;justify-content:center;flex-shrink:0;}\n";
        f << ".logo-text h1{font-size:1.25rem;font-weight:700;}\n";
        f << ".logo-text p{font-size:0.75rem;color:var(--muted);font-family:'JetBrains Mono',monospace;}\n";
        f << ".meta{text-align:right;font-size:0.75rem;color:var(--muted);font-family:'JetBrains Mono',monospace;line-height:1.6;}\n";
        f << ".grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.5rem;}\n";
        f << ".grid-2{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:1.5rem;}\n";
        f << ".card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.25rem 1.5rem;margin-bottom:1.5rem;}\n";
        f << ".stat-card{position:relative;overflow:hidden;margin-bottom:0;}\n";
        f << ".stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--accent),var(--accent2));}\n";
        f << ".stat-label{font-size:0.7rem;text-transform:uppercase;letter-spacing:0.08em;color:var(--muted);margin-bottom:0.5rem;font-weight:500;}\n";
        f << ".stat-value{font-size:1.75rem;font-weight:700;font-family:'JetBrains Mono',monospace;line-height:1;}\n";
        f << ".stat-sub{font-size:0.7rem;color:var(--muted);margin-top:0.35rem;}\n";
        f << ".stat-value.danger{color:var(--danger);}.stat-value.success{color:var(--success);}.stat-value.warn{color:var(--warn);}.stat-value.accent{color:var(--accent);}\n";
        f << ".card h2{font-size:0.8rem;text-transform:uppercase;letter-spacing:0.08em;color:var(--muted);margin-bottom:1.25rem;font-weight:600;}\n";
        f << ".chart-wrap{position:relative;height:280px;}\n";
        f << ".timeline-wrap{position:relative;height:320px;}\n";
        f << ".app-list{display:flex;flex-direction:column;gap:0.6rem;}\n";
        f << ".app-row{display:flex;align-items:center;gap:0.75rem;}\n";
        f << ".app-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;}\n";
        f << ".app-name{font-size:0.85rem;font-weight:500;flex:1;}\n";
        f << ".app-bar-wrap{flex:2;background:var(--surface2);border-radius:4px;height:6px;overflow:hidden;}\n";
        f << ".app-bar{height:100%;border-radius:4px;}\n";
        f << ".app-count{font-size:0.75rem;color:var(--muted);font-family:'JetBrains Mono',monospace;min-width:60px;text-align:right;}\n";
        f << ".domain-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:0.5rem;max-height:340px;overflow-y:auto;}\n";
        f << ".domain-item{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:0.6rem 0.75rem;display:flex;align-items:center;justify-content:space-between;gap:0.5rem;}\n";
        f << ".domain-name{font-size:0.72rem;font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;}\n";
        f << ".domain-badge{font-size:0.65rem;padding:0.15rem 0.5rem;border-radius:20px;font-weight:600;white-space:nowrap;}\n";
        f << ".badge-youtube{background:#ef444420;color:#ef4444;}.badge-google{background:#22d3ee20;color:#22d3ee;}.badge-microsoft{background:#6366f120;color:#6366f1;}.badge-github{background:#f59e0b20;color:#f59e0b;}.badge-dns{background:#64748b20;color:#64748b;}.badge-https{background:#10b98120;color:#10b981;}.badge-default{background:#8b5cf620;color:#8b5cf6;}\n";
        f << ".footer{text-align:center;margin-top:2rem;font-size:0.7rem;color:var(--muted);font-family:'JetBrains Mono',monospace;}\n";
        f << "@media print{.topbar{display:none!important;}body{padding:0.5rem;background:#fff!important;color:#0f172a!important;}.card{background:#f8fafc!important;border:1px solid #e2e8f0!important;break-inside:avoid;}.stat-value,.stat-value.accent,.stat-value.success,.stat-value.danger,.stat-value.warn{color:#0f172a!important;}.header{border-bottom:2px solid #6366f1!important;}.print-footer{display:block!important;}}.print-footer{display:none;text-align:center;margin-top:1rem;padding-top:1rem;border-top:1px solid #e2e8f0;font-size:0.7rem;color:#64748b;font-family:JetBrains Mono,monospace;}\n";
        f << "</style>\n</head>\n<body>\n";
        f << "<div class=\"topbar\"><div class=\"topbar-inner\">"
          "<span style=\"font-size:0.9rem\">&#9790;</span>"
          "<label class=\"sw\"><input type=\"checkbox\" id=\"tog\" onchange=\"toggleTheme()\"><span class=\"sl\"></span></label>"
          "<span style=\"font-size:0.9rem\">&#9728;</span>"
          "<span class=\"tl\" id=\"tl\">Dark Mode</span>"
          "<div class=\"topbar-divider\"></div>"
          "<div class=\"export-group\">"
          "<button class=\"export-btn\" onclick=\"exportCSV()\"><span class=\"icon\">&#128190;</span> Export CSV</button>"
          "<button class=\"export-btn\" onclick=\"window.print()\"><span class=\"icon\">&#128438;</span> Export PDF</button>"
          "</div>"
          "</div></div>\n";

        // Header
        f << "<div class=\"header\"><div class=\"logo\"><div class=\"logo-icon\">"
             "<svg width=\"42\" height=\"42\" viewBox=\"0 0 42 42\" xmlns=\"http://www.w3.org/2000/svg\">"
             "<rect width=\"42\" height=\"42\" rx=\"10\" fill=\"url(#logoGrad)\"/>"
             "<defs><linearGradient id=\"logoGrad\" x1=\"0\" y1=\"0\" x2=\"42\" y2=\"42\">"
             "<stop offset=\"0\" stop-color=\"#6366f1\"/><stop offset=\"1\" stop-color=\"#22d3ee\"/></linearGradient></defs>"
             "<path d=\"M21 9 L31 13 V21 C31 27 26 31 21 33 C16 31 11 27 11 21 V13 Z\" "
             "fill=\"none\" stroke=\"#ffffff\" stroke-width=\"2\" stroke-linejoin=\"round\"/>"
             "<path d=\"M16 21 L19.5 24.5 L27 16\" fill=\"none\" stroke=\"#ffffff\" stroke-width=\"2.2\" "
             "stroke-linecap=\"round\" stroke-linejoin=\"round\"/>"
             "</svg>"
             "</div>";
        f << "<div class=\"logo-text\"><h1>DPI Engine Report</h1><p>Deep Packet Inspection v2.0</p></div></div>";
        f << "<div class=\"meta\"><div>" << time_buf << "</div><div>" << data.input_file << "</div></div></div>\n";

        // Stats cards
        f << "<div class=\"grid-4\">";
        f << "<div class=\"card stat-card\"><div class=\"stat-label\">Total Packets</div><div class=\"stat-value accent\">" << data.total_packets << "</div><div class=\"stat-sub\">" << fmtBytes(data.total_bytes) << " total</div></div>";
        f << "<div class=\"card stat-card\"><div class=\"stat-label\">Forwarded</div><div class=\"stat-value success\">" << data.forwarded << "</div><div class=\"stat-sub\">TCP: " << data.tcp_packets << " | UDP: " << data.udp_packets << "</div></div>";
        f << "<div class=\"card stat-card\"><div class=\"stat-label\">Dropped / Blocked</div><div class=\"stat-value danger\">" << data.dropped << "</div><div class=\"stat-sub\">" << std::fixed << std::setprecision(1) << drop_pct << "% of traffic</div></div>";
        f << "<div class=\"card stat-card\"><div class=\"stat-label\">Apps Detected</div><div class=\"stat-value warn\">" << sorted_apps.size() << "</div><div class=\"stat-sub\">" << data.detected_snis.size() << " unique domains</div></div>";
        f << "</div>\n";

        // Pie + App breakdown
        f << "<div class=\"grid-2\">";
        f << "<div class=\"card\"><h2>Traffic Distribution</h2><div class=\"chart-wrap\"><canvas id=\"pieChart\"></canvas></div></div>";
        f << "<div class=\"card\"><h2>Application Breakdown</h2><div class=\"app-list\">";

        uint64_t max_count = sorted_apps.empty() ? 1 : sorted_apps[0].second;
        for (int i = 0; i < (int)sorted_apps.size() && i < 10; i++) {
            auto [app, count] = sorted_apps[i];
            double pct = 100.0 * count / (data.total_packets > 0 ? data.total_packets : 1);
            double bar_w = 100.0 * count / max_count;
            std::string color = colors[i % colors.size()];
            f << "<div class=\"app-row\">";
            f << "<div class=\"app-dot\" style=\"background:" << color << "\"></div>";
            f << "<div class=\"app-name\">" << appTypeToString(app) << "</div>";
            f << "<div class=\"app-bar-wrap\"><div class=\"app-bar\" style=\"width:" << (int)bar_w << "%;background:" << color << "\"></div></div>";
            f << "<div class=\"app-count\">" << count << " <span style=\"color:#64748b\">" << std::fixed << std::setprecision(1) << pct << "%</span></div>";
            f << "</div>";
        }

        if (!data.blocked_rules.empty()) {
            f << "<div style=\"margin-top:0.75rem;padding:0.75rem;background:#ef444410;border:1px solid #ef444430;border-radius:8px;\">";
            f << "<div style=\"font-size:0.7rem;color:#ef4444;font-weight:600;margin-bottom:0.4rem;\">BLOCKED RULES</div>";
            f << "<div style=\"display:flex;flex-wrap:wrap;gap:0.4rem;\">";
            for (const auto& rule : data.blocked_rules)
                f << "<span style=\"font-size:0.7rem;padding:0.2rem 0.6rem;background:#ef444420;border:1px solid #ef444440;border-radius:20px;color:#ef4444;font-family:'JetBrains Mono',monospace;\">" << rule << "</span>";
            f << "</div></div>";
        }
        f << "</div></div></div>\n";

        // Timeline Graph
        // Top Talkers section
        if (!data.top_talkers.empty()) {
            uint64_t max_talker = data.top_talkers[0].second;
            f << "<div class=\"card\"><h2>&#128293; Top Talkers — Highest Traffic Domains</h2>";
            int rank = 1;
            for (const auto& [domain, count] : data.top_talkers) {
                if (rank > 10) break;
                double bar_w = max_talker > 0 ? (100.0 * count / max_talker) : 0;
                std::string rank_class = rank == 1 ? "top1" : rank == 2 ? "top2" : rank == 3 ? "top3" : "";
                f << "<div class=\"talker-row\">";
                f << "<div class=\"talker-rank " << rank_class << "\">" << rank << "</div>";
                f << "<div class=\"talker-name\" title=\"" << domain << "\">" << domain << "</div>";
                f << "<div class=\"talker-bar-wrap\"><div class=\"talker-bar\" style=\"width:" << (int)bar_w << "%\"></div></div>";
                f << "<div class=\"talker-count\">" << count << " pkts</div>";
                f << "</div>";
                rank++;
            }
            f << "</div>\n";
        }

        f << "<div class=\"card\"><h2>&#128200; Traffic Timeline — Packets per Second by App</h2>";
        f << "<div class=\"timeline-wrap\"><canvas id=\"timelineChart\"></canvas></div></div>\n";

        // Domains
        f << "<div class=\"card\"><h2>Detected Domains &amp; SNIs</h2>";
        f << "<div class=\"domain-controls\">"
             "<div class=\"search-box\"><span class=\"icon\">&#128269;</span>"
             "<input type=\"text\" id=\"domainSearch\" placeholder=\"Search domains...\" oninput=\"filterDomains()\"></div>"
             "<div class=\"filter-group\">"
             "<button class=\"filter-btn active\" data-filter=\"all\" onclick=\"setFilter(this,'all')\">All</button>"
             "<button class=\"filter-btn\" data-filter=\"blocked\" onclick=\"setFilter(this,'blocked')\">Blocked</button>"
             "<button class=\"filter-btn\" data-filter=\"allowed\" onclick=\"setFilter(this,'allowed')\">Allowed</button>"
             "</div></div>";
        f << "<div class=\"domain-grid\" id=\"domainGrid\">";

        auto getBadge = [](AppType app) -> std::string {
            switch(app) {
                case AppType::YOUTUBE: return "badge-youtube";
                case AppType::GOOGLE: return "badge-google";
                case AppType::MICROSOFT: return "badge-microsoft";
                case AppType::GITHUB: return "badge-github";
                case AppType::DNS: return "badge-dns";
                case AppType::HTTPS: return "badge-https";
                default: return "badge-default";
            }
        };

        std::string csv_rows_js;
        for (const auto& [sni, app] : data.detected_snis) {
            bool is_blocked = false;
            for (const auto& rule : data.blocked_rules) {
                if (rule.rfind("Domain: ",0)==0 && sni.find(rule.substr(8)) != std::string::npos) { is_blocked = true; break; }
                if (rule.rfind("App: ",0)==0 && appTypeToString(app) == rule.substr(5)) { is_blocked = true; break; }
            }
            f << "<div class=\"domain-item\" data-domain=\"" << sni << "\" data-status=\"" << (is_blocked ? "blocked" : "allowed") << "\">";
            f << "<div class=\"domain-name\" title=\"" << sni << "\">" << sni << "</div>";
            f << "<span class=\"domain-badge " << getBadge(app) << "\">" << appTypeToString(app) << "</span>";
            if (is_blocked) f << "<span style=\"font-size:0.65rem;color:var(--danger);margin-left:0.3rem;\">&#128683;</span>";
            f << "</div>";
            if (!csv_rows_js.empty()) csv_rows_js += ",";
            csv_rows_js += "[\"" + sni + "\",\"" + appTypeToString(app) + "\"]";
        }
        f << "</div>";
        f << "<div class=\"no-results\" id=\"noResults\">No domains match your search/filter</div>";
        f << "</div>\n";

        f << "<div class=\"print-footer\">"
             "<svg width=\"20\" height=\"20\" viewBox=\"0 0 42 42\" style=\"vertical-align:middle;margin-right:6px\">"
             "<rect width=\"42\" height=\"42\" rx=\"10\" fill=\"#6366f1\"/>"
             "<path d=\"M21 9 L31 13 V21 C31 27 26 31 21 33 C16 31 11 27 11 21 V13 Z\" "
             "fill=\"none\" stroke=\"#fff\" stroke-width=\"2.5\" stroke-linejoin=\"round\"/>"
             "<path d=\"M16 21 L19.5 24.5 L27 16\" fill=\"none\" stroke=\"#fff\" stroke-width=\"2.8\" "
             "stroke-linecap=\"round\" stroke-linejoin=\"round\"/>"
             "</svg>"
             "DPI Engine v2.0 Report &nbsp;&#183;&nbsp; Confidential &nbsp;&#183;&nbsp; Generated " << time_buf << "</div>\n";
        f << "<div class=\"footer\">Generated by DPI Engine v2.0 &nbsp;&#183;&nbsp; Deep Packet Inspection System</div>\n";

        // Charts JS
        f << "<script>\n";

        // Pie chart
        f << "new Chart(document.getElementById('pieChart').getContext('2d'), {\n";
        f << "  type: 'doughnut',\n";
        f << "  data: { labels: [" << chart_labels << "], datasets: [{ data: [" << chart_data << "], backgroundColor: [" << chart_colors << "], borderColor: '#111827', borderWidth: 2, hoverOffset: 8 }] },\n";
        f << "  options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#e2e8f0', font: { family: 'Inter', size: 11 }, padding: 12, usePointStyle: true } }, tooltip: { backgroundColor: '#1a2235', borderColor: '#1e2d45', borderWidth: 1, titleColor: '#e2e8f0', bodyColor: '#94a3b8' } }, cutout: '65%' }\n";
        f << "});\n\n";

        // Timeline chart
        f << "new Chart(document.getElementById('timelineChart').getContext('2d'), {\n";
        f << "  type: 'line',\n";
        f << "  data: {\n";
        f << "    labels: [" << timeline_labels << "],\n";
        f << "    datasets: [\n" << timeline_ds_js << "\n    ]\n";
        f << "  },\n";
        f << "  options: {\n";
        f << "    responsive: true,\n";
        f << "    maintainAspectRatio: false,\n";
        f << "    interaction: { mode: 'index', intersect: false },\n";
        f << "    plugins: {\n";
        f << "      legend: { position: 'top', labels: { color: '#e2e8f0', font: { family: 'Inter', size: 11 }, padding: 16, usePointStyle: true } },\n";
        f << "      tooltip: { backgroundColor: '#1a2235', borderColor: '#1e2d45', borderWidth: 1, titleColor: '#e2e8f0', bodyColor: '#94a3b8' }\n";
        f << "    },\n";
        f << "    scales: {\n";
        f << "      x: { grid: { color: '#1e2d45' }, ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 }, maxTicksLimit: 20 } },\n";
        f << "      y: { grid: { color: '#1e2d45' }, ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }, title: { display: true, text: 'Packets/sec', color: '#64748b' } }\n";
        f << "    }\n";
        f << "  }\n";
        f << "});\n";
        f << "let currentFilter='all';\n";
        f << "function setFilter(btn,f){\n";
        f << "  currentFilter=f;\n";
        f << "  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));\n";
        f << "  btn.classList.add('active');\n";
        f << "  filterDomains();\n";
        f << "}\n";
        f << "function filterDomains(){\n";
        f << "  const q=document.getElementById('domainSearch').value.toLowerCase();\n";
        f << "  const items=document.querySelectorAll('.domain-item');\n";
        f << "  let visible=0;\n";
        f << "  items.forEach(item=>{\n";
        f << "    const domain=item.getAttribute('data-domain').toLowerCase();\n";
        f << "    const status=item.getAttribute('data-status');\n";
        f << "    const matchSearch=domain.includes(q);\n";
        f << "    const matchFilter=currentFilter==='all'||status===currentFilter;\n";
        f << "    if(matchSearch&&matchFilter){item.classList.remove('hidden');visible++;}\n";
        f << "    else{item.classList.add('hidden');}\n";
        f << "  });\n";
        f << "  document.getElementById('noResults').style.display=visible===0?'block':'none';\n";
        f << "}\n";
        f << "const csvData=[" << csv_rows_js << "];\n";
        f << "const appStats=[";
        {
            bool first = true;
            for (const auto& [app, count] : data.app_counts) {
                if (!first) f << ",";
                f << "[\"" << appTypeToString(app) << "\"," << count << "]";
                first = false;
            }
        }
        f << "];\n";
        f << "function exportCSV(){\n";
        f << "  let csv='DPI Engine v2.0 - Network Traffic Report\\n';\n";
        f << "  csv+='Generated: " << time_buf << "\\n';\n";
        f << "  csv+='Source File: " << data.input_file << "\\n';\n";
        f << "  csv+='Total Packets: " << data.total_packets << "\\n';\n";
        f << "  csv+='Forwarded: " << data.forwarded << ", Dropped: " << data.dropped << "\\n';\n";
        f << "  csv+='\\n';\n";
        f << "  csv+='Domain,Application\\n';\n";
        f << "  csvData.forEach(r=>csv+=r[0]+','+r[1]+'\\n');\n";
        f << "  csv+='\\nApplication,PacketCount\\n';\n";
        f << "  appStats.forEach(r=>csv+=r[0]+','+r[1]+'\\n');\n";
        f << "  const blob=new Blob([csv],{type:'text/csv'});\n";
        f << "  const a=document.createElement('a');\n";
        f << "  a.href=URL.createObjectURL(blob);\n";
        f << "  a.download='dpi_report.csv';\n";
        f << "  a.click();\n";
        f << "}\n";
        f << "function toggleTheme(){var b=document.body,tog=document.getElementById('tog'),tl=document.getElementById('tl');if(tog.checked){b.classList.add('light');tl.textContent='Light Mode';localStorage.setItem('dpi-theme','light');}else{b.classList.remove('light');tl.textContent='Dark Mode';localStorage.setItem('dpi-theme','dark');}}\n";
        f << "if(localStorage.getItem('dpi-theme')==='light'){document.body.classList.add('light');document.getElementById('tog').checked=true;document.getElementById('tl').textContent='Light Mode';}\n";
        f << "</script>\n</body>\n</html>";

        f.close();
        return true;
    }
};

} // namespace DPI
