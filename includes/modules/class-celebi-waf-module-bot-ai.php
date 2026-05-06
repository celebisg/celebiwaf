<?php
if (!defined('ABSPATH')) { exit; }

class CELEBI_WAF_Module_Bot_AI {
    public function inspect($context) {
        if (get_option('celebi_waf_bot_ai_enabled', '1') !== '1') { return null; }

        $score = 0;
        $reasons = [];
        $ua = strtolower($context['user_agent']);
        $uri = strtolower($context['uri']);

        if (!$ua) { $score += 25; $reasons[] = 'User-Agent boş'; }
        if (preg_match('/headless|phantom|selenium|puppeteer|playwright/i', $ua)) { $score += 45; $reasons[] = 'Headless otomasyon izi'; }
        if (preg_match('/wp-login|xmlrpc\.php|wp-json/i', $uri)) { $score += 10; $reasons[] = 'Hassas endpoint'; }

        $ipKey = 'celebi_waf_ai_ip_' . md5($context['ip']);
        $uriKey = 'celebi_waf_ai_uri_' . md5($context['ip'] . $uri);
        $ipHits = intval(get_transient($ipKey)) + 1;
        $uriHits = intval(get_transient($uriKey)) + 1;
        set_transient($ipKey, $ipHits, MINUTE_IN_SECONDS);
        set_transient($uriKey, $uriHits, MINUTE_IN_SECONDS);

        if ($ipHits > 80) { $score += 35; $reasons[] = 'Dakikalık IP davranışı anormal'; }
        if ($uriHits > 25) { $score += 30; $reasons[] = 'Aynı URL tekrar paterni'; }

        $threshold = max(30, min(100, intval(get_option('celebi_waf_bot_ai_threshold', 75))));
        if ($score >= $threshold) {
            return [
                'module' => 'Gelişmiş Bot AI',
                'attack_type' => implode(', ', $reasons),
                'rule_name' => 'AI Davranış Skoru: ' . $score,
                'risk_score' => min(100, $score),
                'action' => 'challenge'
            ];
        }
        return null;
    }
}
