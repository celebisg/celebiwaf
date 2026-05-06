<?php
if (!defined('ABSPATH')) { exit; }

class CELEBI_WAF_Rules {
    public static function all_enabled() {
        global $wpdb;
        return $wpdb->get_results("SELECT * FROM " . CELEBI_WAF_DB::rules_table() . " WHERE enabled=1 ORDER BY risk_score DESC", ARRAY_A);
    }

    public static function evaluate($payload) {
        foreach (self::all_enabled() as $rule) {
            $pattern = '/' . str_replace('/', '\/', $rule['pattern']) . '/i';
            if (@preg_match($pattern, $payload)) {
                return [
                    'matched' => true,
                    'rule_name' => $rule['rule_name'],
                    'category' => $rule['category'],
                    'risk_score' => intval($rule['risk_score']),
                    'action' => $rule['action']
                ];
            }
        }
        return ['matched' => false, 'risk_score' => 5, 'category' => 'Normal Trafik', 'rule_name' => '', 'action' => 'allow'];
    }
}
