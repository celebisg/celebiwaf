<?php
if (!defined('ABSPATH')) { exit; }

class CELEBI_WAF_Module_Threat_Intel {
    public function inspect($context) {
        if (get_option('celebi_waf_threat_intel_enabled', '1') !== '1') { return null; }
        $ip = $context['ip'];
        $rep = self::reputation($ip);
        if ($rep['score'] >= intval(get_option('celebi_waf_threat_block_threshold', 90))) {
            return [
                'module' => 'Threat Intelligence',
                'attack_type' => 'Yüksek riskli IP reputation',
                'rule_name' => $rep['source'],
                'risk_score' => $rep['score'],
                'action' => 'block'
            ];
        }
        if ($rep['score'] >= intval(get_option('celebi_waf_threat_challenge_threshold', 70))) {
            return [
                'module' => 'Threat Intelligence',
                'attack_type' => 'Şüpheli IP reputation',
                'rule_name' => $rep['source'],
                'risk_score' => $rep['score'],
                'action' => 'challenge'
            ];
        }
        return null;
    }

    public static function reputation($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return ['score'=>0, 'source'=>'local/private'];
        }

        $cache_key = 'celebi_waf_rep_' . md5($ip);
        $cached = get_transient($cache_key);
        if (is_array($cached)) { return $cached; }

        $score = 0;
        $source = 'local heuristics';

        $manual = json_decode((string) get_option('celebi_waf_threat_manual_reputation', '[]'), true);
        if (is_array($manual)) {
            foreach ($manual as $row) {
                if (is_array($row) && isset($row['ip']) && $row['ip'] === $ip) {
                    $manual_score = max(0, min(100, intval($row['score'] ?? 0)));
                    $manual_source = !empty($row['feed']) ? sanitize_text_field($row['feed']) : 'manual reputation';
                    $result = ['score'=>$manual_score, 'source'=>$manual_source, 'action'=>sanitize_key($row['action'] ?? 'monitor')];
                    set_transient($cache_key, $result, max(5, intval(get_option('celebi_waf_threat_cache_ttl', 360))) * MINUTE_IN_SECONDS);
                    return $result;
                }
            }
        }

        // Basit reputation heuristics: sık görülen scanner ASN/IP feed entegrasyonu için temel.
        $prefix_text = get_option('celebi_waf_threat_bad_prefixes', "45.\n185.\n193.\n198.\n89.248.");
        $badPrefixes = array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', (string) $prefix_text)));
        foreach ($badPrefixes as $prefix) {
            if ($prefix !== '' && strpos($ip, $prefix) === 0) { $score += 20; $source = 'prefix heuristic'; }
        }

        $feed = CELEBI_WAF_Utils::safe_remote_url(get_option('celebi_waf_threat_feed_url', ''));
        if ($feed) {
            $response = wp_remote_get($feed, ['timeout'=>5]);
            if (!is_wp_error($response)) {
                $body = wp_remote_retrieve_body($response);
                if ($body && strpos($body, $ip) !== false) {
                    $score = 95;
                    $source = 'external threat feed';
                }
            }
        }

        $result = ['score'=>min(100, $score), 'source'=>$source];
        set_transient($cache_key, $result, max(5, intval(get_option('celebi_waf_threat_cache_ttl', 360))) * MINUTE_IN_SECONDS);
        return $result;
    }
}
