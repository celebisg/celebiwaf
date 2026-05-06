<?php
if (!defined('ABSPATH')) { exit; }

class CELEBI_WAF_Module_Bot {
    public function inspect($context) {
        $ua = strtolower($context['user_agent']);
        $score = 0;
        $reasons = [];

        if (!$ua || strlen($ua) < 8) { $score += 30; $reasons[] = 'Boş/Kısa User-Agent'; }
        if (preg_match('/bot|crawler|spider|scrapy|headless|phantom|selenium|puppeteer/i', $ua)) { $score += 45; $reasons[] = 'Bot imzası'; }
        if (preg_match('/sqlmap|nikto|acunetix|masscan|zgrab|curl|python-requests/i', $ua)) { $score += 70; $reasons[] = 'Güvenlik tarama aracı'; }

        $key = 'celebi_waf_ua_' . md5($context['ip'] . $ua);
        $seen = intval(get_transient($key));
        set_transient($key, $seen + 1, MINUTE_IN_SECONDS);
        if ($seen > 40) { $score += 30; $reasons[] = 'Anormal User-Agent frekansı'; }

        if ($score >= 70) {
            return [
                'module' => 'Bot Engelleme',
                'attack_type' => implode(', ', $reasons),
                'rule_name' => 'Davranışsal Bot Analizi',
                'risk_score' => min(100, $score),
                'action' => 'challenge'
            ];
        }
        return null;
    }
}
