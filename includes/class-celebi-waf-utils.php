<?php
if (!defined('ABSPATH')) { exit; }

class CELEBI_WAF_Utils {
    public static function ip() {
        $keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];
        foreach ($keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = trim(explode(',', sanitize_text_field($_SERVER[$key]))[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) { return $ip; }
            }
        }
        return '0.0.0.0';
    }

    public static function request_payload() {
        $clean = function ($value) use (&$clean) {
            if (is_array($value)) { return array_map($clean, $value); }
            return sanitize_textarea_field(wp_unslash((string) $value));
        };
        return wp_json_encode([
            'uri' => esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'] ?? '')),
            'method' => sanitize_key($_SERVER['REQUEST_METHOD'] ?? ''),
            'get' => $clean($_GET),
            'post' => $clean($_POST),
            'cookie' => $clean($_COOKIE),
            'ua' => sanitize_textarea_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? '')),
            'referer' => esc_url_raw(wp_unslash($_SERVER['HTTP_REFERER'] ?? ''))
        ]);
    }

    public static function should_sample() {
        $rate = max(1, min(100, intval(get_option('celebi_waf_sampling_rate', 100))));
        return random_int(1, 100) <= $rate;
    }


    public static function safe_remote_url($url) {
        $url = esc_url_raw(trim((string) $url));
        if (!$url) { return ''; }
        $parts = wp_parse_url($url);
        if (empty($parts['scheme']) || empty($parts['host']) || !in_array($parts['scheme'], ['http','https'], true)) { return ''; }
        $host = $parts['host'];
        $ip = filter_var($host, FILTER_VALIDATE_IP) ? $host : gethostbyname($host);
        if ($ip && filter_var($ip, FILTER_VALIDATE_IP) && !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) { return ''; }
        return $url;
    }

    public static function json_success($data = []) {
        wp_send_json_success($data);
    }

    public static function admin_check() {
        check_ajax_referer('celebi_waf_nonce', 'nonce');
        if (!current_user_can('manage_options')) { wp_send_json_error('Yetkisiz işlem'); }
    }
}
