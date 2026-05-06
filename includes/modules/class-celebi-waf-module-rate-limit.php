<?php
if (!defined('ABSPATH')) { exit; }

class CELEBI_WAF_Module_Rate_Limit {
    public function inspect($context) {
        $limit = max(10, intval(get_option('celebi_waf_rate_limit', 120)));
        $key = 'celebi_waf_rate_' . md5($context['ip']);
        $count = intval(get_transient($key)) + 1;
        set_transient($key, $count, MINUTE_IN_SECONDS);

        if ($count > $limit) {
            return [
                'module' => 'DDoS Koruma Katmanı',
                'attack_type' => 'Rate limit aşıldı',
                'rule_name' => 'IP Dakikalık Limit',
                'risk_score' => 90,
                'action' => 'challenge'
            ];
        }
        return null;
    }
}
