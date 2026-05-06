<?php
if (!defined('ABSPATH')) { exit; }

class CELEBI_WAF_Logger {
    public static function queue($event) {
        $queue = get_transient('celebi_waf_log_queue');
        if (!is_array($queue)) { $queue = []; }
        $queue[] = $event;
        if (count($queue) >= 20) {
            self::flush_array($queue);
            delete_transient('celebi_waf_log_queue');
        } else {
            set_transient('celebi_waf_log_queue', $queue, 10 * MINUTE_IN_SECONDS);
        }
    }

    public static function flush() {
        $queue = get_transient('celebi_waf_log_queue');
        if (is_array($queue) && $queue) {
            self::flush_array($queue);
            delete_transient('celebi_waf_log_queue');
        }
    }

    private static function flush_array($queue) {
        global $wpdb;
        $table = CELEBI_WAF_DB::events_table();
        foreach ($queue as $e) {
            $wpdb->insert($table, [
                'event_time' => current_time('mysql'),
                'ip' => sanitize_text_field($e['ip'] ?? ''),
                'country' => sanitize_text_field($e['country'] ?? ''),
                'lat' => isset($e['lat']) ? floatval($e['lat']) : null,
                'lng' => isset($e['lng']) ? floatval($e['lng']) : null,
                'method' => sanitize_text_field($e['method'] ?? ''),
                'uri' => esc_url_raw($e['uri'] ?? ''),
                'user_agent' => sanitize_textarea_field($e['user_agent'] ?? ''),
                'attack_type' => sanitize_text_field($e['attack_type'] ?? ''),
                'module' => sanitize_text_field($e['module'] ?? ''),
                'rule_name' => sanitize_text_field($e['rule_name'] ?? ''),
                'risk_score' => intval($e['risk_score'] ?? 0),
                'action' => sanitize_text_field($e['action'] ?? 'izlendi')
            ]);
        }
    }

    public static function cleanup() {
        global $wpdb;
        $wpdb->query("DELETE FROM " . CELEBI_WAF_DB::events_table() . " WHERE event_time < DATE_SUB(NOW(), INTERVAL 30 DAY)");
        $wpdb->query("DELETE FROM " . CELEBI_WAF_DB::ip_rules_table() . " WHERE expires_at IS NOT NULL AND expires_at < NOW()");
    }
}

add_action('celebi_waf_flush_logs', ['CELEBI_WAF_Logger', 'flush']);
add_action('celebi_waf_cleanup', ['CELEBI_WAF_Logger', 'cleanup']);
