<?php
if (!defined('ABSPATH')) { exit; }

class CELEBI_WAF_Module_Challenge {
    public function inspect($context) {
        global $wpdb;
        $this->cleanup();
        $rule = $wpdb->get_row($wpdb->prepare("SELECT * FROM " . CELEBI_WAF_DB::ip_rules_table() . " WHERE ip=%s LIMIT 1", $context['ip']), ARRAY_A);
        if (!$rule) { return null; }
        if ($rule['rule_type'] === 'allow') { return ['allow' => true]; }
        if ($rule['rule_type'] === 'block') {
            return [
                'module' => 'IP Challenge / Bot Engelleme',
                'attack_type' => 'IP Blok Listesi',
                'rule_name' => 'Manuel IP Block',
                'risk_score' => 100,
                'action' => 'block'
            ];
        }
        return [
            'module' => 'IP Challenge / Bot Engelleme',
            'attack_type' => 'IP Challenge Listesi',
            'rule_name' => 'IP Challenge',
            'risk_score' => 75,
            'action' => 'challenge'
        ];
    }

    public function add_rule($ip, $type='challenge', $note='', $minutes=60) {
        global $wpdb;
        if (!filter_var($ip, FILTER_VALIDATE_IP)) { return false; }
        $type = in_array($type, ['challenge', 'block', 'allow'], true) ? $type : 'challenge';
        $expires = $type === 'allow' ? null : date('Y-m-d H:i:s', current_time('timestamp') + max(5, intval($minutes)) * 60);
        return $wpdb->replace(CELEBI_WAF_DB::ip_rules_table(), [
            'created_at' => current_time('mysql'),
            'ip' => $ip,
            'rule_type' => $type,
            'note' => $note,
            'expires_at' => $expires
        ]);
    }

    public function render_challenge($ip) {
        if (get_option('celebi_waf_challenge_enabled', '1') !== '1') {
            wp_die('Erişim CELEBI WAF tarafından engellendi.', 'CELEBI WAF', ['response' => 403]);
        }

        $cookie_key = 'celebi_waf_pass_' . md5($ip . AUTH_SALT);
        $cookie_value = isset($_COOKIE[$cookie_key]) ? sanitize_text_field(wp_unslash($_COOKIE[$cookie_key])) : '';
        if ($cookie_value && hash_equals($cookie_value, hash('sha256', $ip . AUTH_SALT))) { return true; }

        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['celebi_waf_answer'], $_POST['celebi_waf_token'])) {
            $posted_token = sanitize_text_field(wp_unslash($_POST['celebi_waf_token']));
            $posted_answer = intval(wp_unslash($_POST['celebi_waf_answer']));
            $expected = intval(get_transient('celebi_waf_math_' . md5($posted_token)));
            if ($expected && $posted_answer === $expected) {
                setcookie($cookie_key, hash('sha256', $ip . AUTH_SALT), time() + intval(get_option('celebi_waf_challenge_ttl', 60)) * 60, COOKIEPATH ?: '/', COOKIE_DOMAIN, is_ssl(), true);
                $redirect = esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'] ?? '/'));
                wp_safe_redirect($redirect ?: home_url('/'));
                exit;
            }
        }

        $a = random_int(2, 9);
        $b = random_int(2, 9);
        $token = wp_generate_password(20, false);
        set_transient('celebi_waf_math_' . md5($token), $a + $b, 10 * MINUTE_IN_SECONDS);

        status_header(403);
        nocache_headers();
        echo '<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CELEBI WAF IP Challenge</title>';
        echo '<style>body{font-family:Arial,sans-serif;background:#f6f7f7;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}.box{background:#fff;border:1px solid #ddd;border-radius:16px;padding:28px;max-width:430px;box-shadow:0 10px 35px rgba(0,0,0,.08)}.logo{width:64px;height:64px;object-fit:contain}input{padding:10px;width:100%;box-sizing:border-box;margin:10px 0}button{background:#0a7f28;color:#fff;border:0;border-radius:8px;padding:11px 16px;cursor:pointer}.muted{color:#666}</style></head><body><div class="box">';
        echo '<img class="logo" src="' . esc_url(CELEBI_WAF_URL . 'assets/admin-logo.png') . '" alt="CELEBI WAF">';
        echo '<h1>Güvenlik Doğrulaması</h1><p class="muted">Bot olmadığınızı doğrulamak için işlemi tamamlayın.</p>';
        echo '<form method="post"><p><strong>' . esc_html($a) . ' + ' . esc_html($b) . ' = ?</strong></p>';
        echo '<input type="hidden" name="celebi_waf_token" value="' . esc_attr($token) . '">';
        echo '<input type="number" name="celebi_waf_answer" required autofocus>';
        echo '<button type="submit">Doğrula ve Devam Et</button></form></div></body></html>';
        exit;
    }

    private function cleanup() {
        global $wpdb;
        $wpdb->query("DELETE FROM " . CELEBI_WAF_DB::ip_rules_table() . " WHERE expires_at IS NOT NULL AND expires_at < NOW()");
    }
}
