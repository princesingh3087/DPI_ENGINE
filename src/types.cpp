#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;

    std::string s = sni;
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // YouTube - PEHLE check karo (Google se pehle!)
    if (s.find("youtube") != std::string::npos ||
        s.find("ytimg") != std::string::npos ||
        s.find("youtu.be") != std::string::npos ||
        s.find("googlevideo") != std::string::npos ||
        s.find("yt3.ggpht") != std::string::npos ||
        s.find("ytgcp") != std::string::npos) {
        return AppType::YOUTUBE;
    }

    // Google
    if (s.find("google") != std::string::npos ||
        s.find("gstatic") != std::string::npos ||
        s.find("googleapis") != std::string::npos ||
        s.find("ggpht") != std::string::npos ||
        s.find("gvt1") != std::string::npos ||
        s.find("googlesyndication") != std::string::npos ||
        s.find("googleusercontent") != std::string::npos ||
        s.find("doubleclick") != std::string::npos) {
        return AppType::GOOGLE;
    }

    // Microsoft - strict matching (t.co hataya, x.com hataya)
    if (s.find("microsoft") != std::string::npos ||
        s.find(".msn.com") != std::string::npos ||
        s.find("office") != std::string::npos ||
        s.find("azure") != std::string::npos ||
        s.find("live.com") != std::string::npos ||
        s.find("outlook") != std::string::npos ||
        s.find(".bing.com") != std::string::npos ||
        s.find("msftstatic") != std::string::npos ||
        s.find("msedge") != std::string::npos ||
        s.find("azureedge") != std::string::npos) {
        return AppType::MICROSOFT;
    }

    // Facebook/Meta
    if (s.find("facebook") != std::string::npos ||
        s.find("fbcdn") != std::string::npos ||
        s.find("fb.com") != std::string::npos ||
        s.find("fbsbx") != std::string::npos ||
        s.find("meta.com") != std::string::npos) {
        return AppType::FACEBOOK;
    }

    // Instagram
    if (s.find("instagram") != std::string::npos ||
        s.find("cdninstagram") != std::string::npos) {
        return AppType::INSTAGRAM;
    }

    // WhatsApp
    if (s.find("whatsapp") != std::string::npos ||
        s.find("wa.me") != std::string::npos) {
        return AppType::WHATSAPP;
    }

    // Twitter/X - sirf actual Twitter domains
    if (s.find("twitter.com") != std::string::npos ||
        s.find("twimg.com") != std::string::npos ||
        s.find("twimg") != std::string::npos) {
        return AppType::TWITTER;
    }

    // Netflix
    if (s.find("netflix") != std::string::npos ||
        s.find("nflxvideo") != std::string::npos ||
        s.find("nflximg") != std::string::npos) {
        return AppType::NETFLIX;
    }

    // Amazon - sirf actual Amazon domains (aws hataya)
    if (s.find("amazon.com") != std::string::npos ||
        s.find("amazon.in") != std::string::npos ||
        s.find("amazonaws.com") != std::string::npos ||
        s.find("amazonvideo") != std::string::npos) {
        return AppType::AMAZON;
    }

    // Apple
    if (s.find("apple.com") != std::string::npos ||
        s.find("icloud.com") != std::string::npos ||
        s.find("mzstatic") != std::string::npos ||
        s.find("itunes") != std::string::npos) {
        return AppType::APPLE;
    }

    // Telegram
    if (s.find("telegram.org") != std::string::npos ||
        s.find("t.me") != std::string::npos) {
        return AppType::TELEGRAM;
    }

    // TikTok
    if (s.find("tiktok") != std::string::npos ||
        s.find("tiktokcdn") != std::string::npos ||
        s.find("musical.ly") != std::string::npos ||
        s.find("bytedance") != std::string::npos) {
        return AppType::TIKTOK;
    }

    // Spotify
    if (s.find("spotify.com") != std::string::npos ||
        s.find("scdn.co") != std::string::npos) {
        return AppType::SPOTIFY;
    }

    // Zoom
    if (s.find("zoom.us") != std::string::npos ||
        s.find("zoom.com") != std::string::npos) {
        return AppType::ZOOM;
    }

    // Discord
    if (s.find("discord.com") != std::string::npos ||
        s.find("discordapp.com") != std::string::npos) {
        return AppType::DISCORD;
    }

    // GitHub
    if (s.find("github.com") != std::string::npos ||
        s.find("githubusercontent.com") != std::string::npos ||
        s.find("github.io") != std::string::npos) {
        return AppType::GITHUB;
    }

    // Cloudflare
    if (s.find("cloudflare.com") != std::string::npos ||
        s.find("cloudflare-dns") != std::string::npos) {
        return AppType::CLOUDFLARE;
    }

    return AppType::HTTPS;
}

} // namespace DPI
