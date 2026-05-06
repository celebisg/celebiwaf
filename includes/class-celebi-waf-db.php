<?php
if (!defined('ABSPATH')) { exit; }

class CELEBI_WAF_DB {
    public static function events_table() { global $wpdb; return $wpdb->prefix . 'celebi_waf_events'; }
    public static function rules_table() { global $wpdb; return $wpdb->prefix . 'celebi_waf_rules'; }
    public static function ip_rules_table() { global $wpdb; return $wpdb->prefix . 'celebi_waf_ip_rules'; }

    public static function activate() {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        dbDelta("CREATE TABLE " . self::events_table() . " (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            event_time DATETIME NOT NULL,
            ip VARCHAR(64) NOT NULL,
            country VARCHAR(80) DEFAULT '',
            lat DECIMAL(10,6) DEFAULT NULL,
            lng DECIMAL(10,6) DEFAULT NULL,
            method VARCHAR(12) DEFAULT '',
            uri TEXT,
            user_agent TEXT,
            attack_type VARCHAR(100) DEFAULT '',
            module VARCHAR(100) DEFAULT '',
            rule_name VARCHAR(150) DEFAULT '',
            risk_score INT DEFAULT 0,
            action VARCHAR(30) DEFAULT 'izlendi',
            PRIMARY KEY (id),
            KEY event_time (event_time),
            KEY ip (ip),
            KEY module (module),
            KEY action (action),
            KEY risk_score (risk_score)
        ) $charset;");

        dbDelta("CREATE TABLE " . self::rules_table() . " (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            created_at DATETIME NOT NULL,
            rule_name VARCHAR(150) NOT NULL,
            category VARCHAR(80) NOT NULL,
            pattern TEXT NOT NULL,
            risk_score INT DEFAULT 80,
            action VARCHAR(30) DEFAULT 'block',
            enabled TINYINT(1) DEFAULT 1,
            PRIMARY KEY (id),
            KEY category (category),
            KEY enabled (enabled)
        ) $charset;");

        dbDelta("CREATE TABLE " . self::ip_rules_table() . " (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            created_at DATETIME NOT NULL,
            ip VARCHAR(64) NOT NULL,
            rule_type VARCHAR(30) NOT NULL DEFAULT 'challenge',
            note TEXT,
            expires_at DATETIME DEFAULT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY ip (ip),
            KEY rule_type (rule_type),
            KEY expires_at (expires_at)
        ) $charset;");

        add_option('celebi_waf_enabled', '1');
        add_option('celebi_waf_sampling_rate', '100');
        add_option('celebi_waf_rate_limit', '120');
        add_option('celebi_waf_auto_challenge', '1');
        add_option('celebi_waf_challenge_enabled', '1');
        add_option('celebi_waf_challenge_ttl', '60');
        add_option('celebi_waf_geo_enabled', '1');
        add_option('celebi_waf_logo_url', CELEBI_WAF_URL . 'assets/admin-logo.png');
        add_option('celebi_waf_saas_enabled', '0');
        add_option('celebi_waf_saas_api_url', '');
        add_option('celebi_waf_saas_api_key', '');
        add_option('celebi_waf_saas_site_id', '');
        add_option('celebi_waf_threat_intel_enabled', '1');
        add_option('celebi_waf_threat_feed_url', '');
        add_option('celebi_waf_edge_enabled', '1');
        add_option('celebi_waf_bot_ai_enabled', '1');
        add_option('celebi_waf_bot_ai_threshold', '75');
        add_option('celebi_waf_threat_manual_reputation', wp_json_encode([
            ['ip'=>'198.51.100.24','feed'=>'Demo Reputation Feed','score'=>72,'action'=>'challenge','note'=>'Örnek orta risk kaydı','updated_at'=>current_time('mysql')],
            ['ip'=>'203.0.113.44','feed'=>'Demo Abuse Feed','score'=>94,'action'=>'block','note'=>'Örnek yüksek risk kaydı','updated_at'=>current_time('mysql')]
        ]));

        self::seed_rules();
        if (!wp_next_scheduled('celebi_waf_flush_logs')) {
            wp_schedule_event(time() + 60, 'minute', 'celebi_waf_flush_logs');
        }
        if (!wp_next_scheduled('celebi_waf_cleanup')) {
            wp_schedule_event(time() + 300, 'hourly', 'celebi_waf_cleanup');
        }
    }

    public static function deactivate() {
        wp_clear_scheduled_hook('celebi_waf_flush_logs');
        wp_clear_scheduled_hook('celebi_waf_cleanup');
    }

    public static function seed_rules() {
        global $wpdb;
        $count = intval($wpdb->get_var("SELECT COUNT(*) FROM " . self::rules_table()));
        if ($count > 0) { return; }

        $rules = [
            ['SQLi: UNION SELECT', 'SQL Injection', 'union\s+select', 95, 'block'],
            ['SQLi: OR 1=1', 'SQL Injection', 'or\s+1\s*=\s*1', 90, 'block'],
            ['SQLi: SLEEP/BENCHMARK', 'SQL Injection', '(sleep|benchmark)\s*\(', 90, 'block'],
            ['SQLi: information_schema', 'SQL Injection', 'information_schema', 90, 'block'],
            ['XSS: script tag', 'XSS', '<script', 95, 'block'],
            ['XSS: javascript protocol', 'XSS', 'javascript:', 85, 'block'],
            ['XSS: event handler', 'XSS', 'on(error|load|click)\s*=', 85, 'block'],
            ['Path Traversal', 'WAF Motoru', '\.\./|etc/passwd|boot\.ini', 90, 'block'],
            ['Command Injection', 'WAF Motoru', ';\s*(cat|wget|curl|bash|sh)|\|\s*(nc|bash|sh)', 95, 'block'],
            ['Bad Bot Tools', 'Bot Engelleme', 'sqlmap|nikto|acunetix|masscan|zgrab|python-requests|curl/[0-9]', 90, 'challenge'],
        ];

        foreach ($rules as $r) {
            $wpdb->insert(self::rules_table(), [
                'created_at' => current_time('mysql'),
                'rule_name' => $r[0],
                'category' => $r[1],
                'pattern' => $r[2],
                'risk_score' => $r[3],
                'action' => $r[4],
                'enabled' => 1
            ]);
        }
    }
}
