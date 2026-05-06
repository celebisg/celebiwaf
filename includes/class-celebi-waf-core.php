<?php
if (!defined('ABSPATH')) { exit; }

class CELEBI_WAF_Core {
    private static $instance = null;
    private $modules = [];
    private $challenge;
    private $geo;

    public static function instance() {
        if (self::$instance === null) { self::$instance = new self(); }
        return self::$instance;
    }

    private function __construct() {
        $this->challenge = new CELEBI_WAF_Module_Challenge();
        $this->geo = new CELEBI_WAF_Module_Geo();
        $this->modules = [
            $this->challenge,
            new CELEBI_WAF_Module_Threat_Intel(),
            new CELEBI_WAF_Module_Rate_Limit(),
            new CELEBI_WAF_Module_Bot_AI(),
            new CELEBI_WAF_Module_Bot(),
            new CELEBI_WAF_Module_WAF()
        ];

        add_action('init', [$this, 'inspect_request'], 0);
        add_action('wp_ajax_celebi_waf_stats', [$this, 'ajax_stats']);
        add_action('wp_ajax_celebi_waf_modules', [$this, 'ajax_modules']);
        add_action('wp_ajax_celebi_waf_rules', [$this, 'ajax_rules']);
        add_action('wp_ajax_celebi_waf_save_rule', [$this, 'ajax_save_rule']);
        add_action('wp_ajax_celebi_waf_delete_rule', [$this, 'ajax_delete_rule']);
        add_action('wp_ajax_celebi_waf_ip_rules', [$this, 'ajax_ip_rules']);
        add_action('wp_ajax_celebi_waf_add_ip_rule', [$this, 'ajax_add_ip_rule']);
        add_action('wp_ajax_celebi_waf_delete_ip_rule', [$this, 'ajax_delete_ip_rule']);
        add_action('wp_ajax_celebi_waf_update_ip_rule_expiry', [$this, 'ajax_update_ip_rule_expiry']);
        add_action('wp_ajax_celebi_waf_logs', [$this, 'ajax_logs']);
        add_action('wp_ajax_celebi_waf_clear_logs', [$this, 'ajax_clear_logs']);
        add_action('wp_ajax_celebi_waf_save_settings', [$this, 'ajax_save_settings']);
        add_action('wp_ajax_celebi_waf_save_enterprise', [$this, 'ajax_save_enterprise']);
        add_action('wp_ajax_celebi_waf_saas_test', [$this, 'ajax_saas_test']);
        add_action('wp_ajax_celebi_waf_edge_rules', [$this, 'ajax_edge_rules']);
        add_action('wp_ajax_celebi_waf_save_bot_ai', [$this, 'ajax_save_bot_ai']);
        add_action('wp_ajax_celebi_waf_save_threat_intel', [$this, 'ajax_save_threat_intel']);
        add_action('wp_ajax_celebi_waf_test_threat_intel', [$this, 'ajax_test_threat_intel']);
        add_action('wp_ajax_celebi_waf_save_version_manifest', [$this, 'ajax_save_version_manifest']);
        add_action('wp_ajax_celebi_waf_check_version_update', [$this, 'ajax_check_version_update']);
        add_action('wp_ajax_celebi_waf_install_version_update', [$this, 'ajax_install_version_update']);
    }

    public function inspect_request() {
        if (is_admin() && !wp_doing_ajax()) { return; }
        if (defined('DOING_CRON') && DOING_CRON) { return; }
        if (get_option('celebi_waf_enabled', '1') !== '1') { return; }

        $context = [
            'ip' => CELEBI_WAF_Utils::ip(),
            'payload' => CELEBI_WAF_Utils::request_payload(),
            'uri' => $_SERVER['REQUEST_URI'] ?? '',
            'method' => $_SERVER['REQUEST_METHOD'] ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        ];

        $decision = null;
        foreach ($this->modules as $module) {
            $result = $module->inspect($context);
            if (is_array($result) && !empty($result['allow'])) { return; }
            if (is_array($result)) { $decision = $result; break; }
        }

        if (!$decision) {
            $decision = [
                'module' => 'Gerçek Zamanlı Trafik İzleme',
                'attack_type' => 'Normal Trafik',
                'rule_name' => '',
                'risk_score' => 5,
                'action' => 'allow'
            ];
        }

        $action = $decision['action'] === 'block' ? 'engellendi' : ($decision['action'] === 'challenge' ? 'challenge' : 'izlendi');

        if (CELEBI_WAF_Utils::should_sample() || $action !== 'izlendi') {
            $geo = $this->geo->lookup($context['ip']);
            $event_payload = [
                'ip' => $context['ip'],
                'country' => $geo['country'],
                'lat' => $geo['lat'],
                'lng' => $geo['lng'],
                'method' => $context['method'],
                'uri' => $context['uri'],
                'user_agent' => $context['user_agent'],
                'attack_type' => $decision['attack_type'],
                'module' => $decision['module'],
                'rule_name' => $decision['rule_name'],
                'risk_score' => $decision['risk_score'],
                'action' => $action
            ];
            CELEBI_WAF_Logger::queue($event_payload);
            CELEBI_WAF_Module_SaaS::push_event($event_payload);
        }

        if ($decision['action'] === 'challenge') {
            if (get_option('celebi_waf_auto_challenge', '1') === '1') {
                $this->challenge->add_rule($context['ip'], 'challenge', 'Otomatik challenge: ' . $decision['attack_type'], intval(get_option('celebi_waf_challenge_ttl', 60)));
            }
            $this->challenge->render_challenge($context['ip']);
        }

        if ($decision['action'] === 'block') {
            status_header(403);
            wp_die('Bu istek CELEBI WAF tarafından engellendi.', 'CELEBI WAF', ['response' => 403]);
        }
    }

    public function ajax_stats() {
        CELEBI_WAF_Utils::admin_check();
        CELEBI_WAF_Logger::flush();
        global $wpdb;
        $t = CELEBI_WAF_DB::events_table();
        $ip_t = CELEBI_WAF_DB::ip_rules_table();

        $cards = [
            'total' => intval($wpdb->get_var("SELECT COUNT(*) FROM $t")),
            'blocked' => intval($wpdb->get_var("SELECT COUNT(*) FROM $t WHERE action IN ('engellendi','challenge')")),
            'last_hour' => intval($wpdb->get_var("SELECT COUNT(*) FROM $t WHERE event_time >= DATE_SUB(NOW(), INTERVAL 1 HOUR)")),
            'bots' => intval($wpdb->get_var("SELECT COUNT(*) FROM $t WHERE module LIKE '%Bot%' OR attack_type LIKE '%Bot%'")),
            'ip_challenge' => intval($wpdb->get_var("SELECT COUNT(*) FROM $ip_t WHERE rule_type='challenge'")),
            'rules' => intval($wpdb->get_var("SELECT COUNT(*) FROM " . CELEBI_WAF_DB::rules_table() . " WHERE enabled=1"))
        ];

        CELEBI_WAF_Utils::json_success([
            'cards' => $cards,
            'timeline' => $wpdb->get_results("SELECT DATE_FORMAT(event_time, '%H:%i') label, COUNT(*) value FROM $t WHERE event_time >= DATE_SUB(NOW(), INTERVAL 12 HOUR) GROUP BY DATE_FORMAT(event_time, '%Y-%m-%d %H:%i') ORDER BY MIN(event_time) ASC LIMIT 80", ARRAY_A),
            'types' => $wpdb->get_results("SELECT attack_type label, COUNT(*) value FROM $t GROUP BY attack_type ORDER BY value DESC LIMIT 10", ARRAY_A),
            'countries' => $wpdb->get_results("SELECT country label, COUNT(*) value FROM $t GROUP BY country ORDER BY value DESC LIMIT 10", ARRAY_A),
            'top_ips' => $wpdb->get_results("SELECT ip label, COUNT(*) value FROM $t GROUP BY ip ORDER BY value DESC LIMIT 10", ARRAY_A),
            'top_urls' => $wpdb->get_results("SELECT uri label, COUNT(*) value FROM $t GROUP BY uri ORDER BY value DESC LIMIT 10", ARRAY_A),
            'map' => $wpdb->get_results("SELECT country, lat, lng, COUNT(*) count FROM $t WHERE lat IS NOT NULL AND lng IS NOT NULL GROUP BY country, lat, lng ORDER BY count DESC LIMIT 50", ARRAY_A),
            'events' => $wpdb->get_results("SELECT * FROM $t ORDER BY id DESC LIMIT 25", ARRAY_A),
        ]);
    }

    public function ajax_modules() {
        CELEBI_WAF_Utils::admin_check();
        global $wpdb;
        $t = CELEBI_WAF_DB::events_table();
        $data = [
            ['name'=>'WAF Motoru', 'count'=>intval($wpdb->get_var("SELECT COUNT(*) FROM $t WHERE module='WAF Motoru'")), 'status'=>'Aktif'],
            ['name'=>'Gerçek Zamanlı Trafik İzleme', 'count'=>intval($wpdb->get_var("SELECT COUNT(*) FROM $t")), 'status'=>'Aktif'],
            ['name'=>'SQL Injection ve XSS Analizi', 'count'=>intval($wpdb->get_var("SELECT COUNT(*) FROM $t WHERE module IN ('SQL Injection','XSS') OR attack_type IN ('SQL Injection','XSS')")), 'status'=>'Aktif'],
            ['name'=>'Bot Engelleme', 'count'=>intval($wpdb->get_var("SELECT COUNT(*) FROM $t WHERE module='Bot Engelleme' OR attack_type LIKE '%Bot%'")), 'status'=>'Aktif'],
            ['name'=>'DDoS Koruma Katmanı', 'count'=>intval($wpdb->get_var("SELECT COUNT(*) FROM $t WHERE module='DDoS Koruma Katmanı'")), 'status'=>'Aktif'],
            ['name'=>'IP Challenge Dinamik Kural Motoru', 'count'=>intval($wpdb->get_var("SELECT COUNT(*) FROM " . CELEBI_WAF_DB::ip_rules_table())), 'status'=>get_option('celebi_waf_challenge_enabled','1')==='1'?'Aktif':'Pasif'],
            ['name'=>'Dinamik Kural Motoru', 'count'=>intval($wpdb->get_var("SELECT COUNT(*) FROM " . CELEBI_WAF_DB::rules_table() . " WHERE enabled=1")), 'status'=>'Aktif'],
            ['name'=>'Async Loglama', 'count'=>intval(count(get_transient('celebi_waf_log_queue') ?: [])), 'status'=>'Aktif'],
            ['name'=>'Gerçek Geo Lookup', 'count'=>intval(get_option('celebi_waf_geo_enabled','1')), 'status'=>get_option('celebi_waf_geo_enabled','1')==='1'?'Aktif':'Pasif'],
        ];
        CELEBI_WAF_Utils::json_success($data);
    }

    public function ajax_rules() {
        CELEBI_WAF_Utils::admin_check();
        global $wpdb;
        CELEBI_WAF_Utils::json_success($wpdb->get_results("SELECT * FROM " . CELEBI_WAF_DB::rules_table() . " ORDER BY id DESC", ARRAY_A));
    }

    public function ajax_save_rule() {
        CELEBI_WAF_Utils::admin_check();
        global $wpdb;
        $id = intval($_POST['id'] ?? 0);
        $data = [
            'created_at' => current_time('mysql'),
            'rule_name' => sanitize_text_field($_POST['rule_name'] ?? ''),
            'category' => sanitize_text_field($_POST['category'] ?? 'WAF Motoru'),
            'pattern' => sanitize_textarea_field($_POST['pattern'] ?? ''),
            'risk_score' => max(1, min(100, intval($_POST['risk_score'] ?? 80))),
            'action' => in_array(sanitize_key($_POST['rule_action'] ?? 'block'), ['block','challenge'], true) ? sanitize_key($_POST['rule_action']) : 'block',
            'enabled' => !empty($_POST['enabled']) ? 1 : 0
        ];
        if ($id) {
            unset($data['created_at']);
            $wpdb->update(CELEBI_WAF_DB::rules_table(), $data, ['id'=>$id]);
        } else {
            $wpdb->insert(CELEBI_WAF_DB::rules_table(), $data);
        }
        CELEBI_WAF_Utils::json_success('Kural kaydedildi.');
    }

    public function ajax_delete_rule() {
        CELEBI_WAF_Utils::admin_check();
        global $wpdb;
        $wpdb->delete(CELEBI_WAF_DB::rules_table(), ['id'=>intval($_POST['id'] ?? 0)]);
        CELEBI_WAF_Utils::json_success('Kural silindi.');
    }

    public function ajax_ip_rules() {
        CELEBI_WAF_Utils::admin_check();
        global $wpdb;
        CELEBI_WAF_Utils::json_success($wpdb->get_results("SELECT * FROM " . CELEBI_WAF_DB::ip_rules_table() . " ORDER BY id DESC LIMIT 200", ARRAY_A));
    }

    public function ajax_add_ip_rule() {
        CELEBI_WAF_Utils::admin_check();
        $rule_type = sanitize_key($_POST['rule_type'] ?? 'challenge');
        if (!in_array($rule_type, ['challenge','block','allow'], true)) { $rule_type = 'challenge'; }
        $ok = $this->challenge->add_rule(sanitize_text_field($_POST['ip'] ?? ''), $rule_type, sanitize_textarea_field($_POST['note'] ?? ''), max(1, min(10080, intval($_POST['minutes'] ?? 60))));
        if (!$ok) { wp_send_json_error('Geçerli IP adresi girin.'); }
        CELEBI_WAF_Utils::json_success('IP kuralı kaydedildi.');
    }

    public function ajax_delete_ip_rule() {
        CELEBI_WAF_Utils::admin_check();
        global $wpdb;
        $wpdb->delete(CELEBI_WAF_DB::ip_rules_table(), ['id'=>intval($_POST['id'] ?? 0)]);
        CELEBI_WAF_Utils::json_success('IP kuralı silindi.');
    }

    public function ajax_update_ip_rule_expiry() {
        CELEBI_WAF_Utils::admin_check();
        global $wpdb;
        $id = intval($_POST['id'] ?? 0);
        $mode = sanitize_key($_POST['mode'] ?? 'minutes');
        $minutes = max(-525600, min(525600, intval($_POST['minutes'] ?? 60)));
        $expires_input = sanitize_text_field(wp_unslash($_POST['expires_at'] ?? ''));
        $table = CELEBI_WAF_DB::ip_rules_table();
        $rule = $wpdb->get_row($wpdb->prepare("SELECT id, rule_type, expires_at FROM $table WHERE id=%d LIMIT 1", $id), ARRAY_A);
        if (!$rule) { wp_send_json_error('IP kuralı bulunamadı.'); }
        if ($mode === 'permanent') {
            $expires_at = null;
        } elseif ($mode === 'exact' && $expires_input !== '') {
            $timestamp = strtotime($expires_input);
            if (!$timestamp) { wp_send_json_error('Geçerli bitiş tarihi girin.'); }
            $expires_at = date('Y-m-d H:i:s', $timestamp);
        } else {
            $base = !empty($rule['expires_at']) ? strtotime($rule['expires_at']) : current_time('timestamp');
            if (!$base) { $base = current_time('timestamp'); }
            $expires_at = date('Y-m-d H:i:s', $base + ($minutes * 60));
        }
        if ($expires_at === null) {
            $updated = $wpdb->query($wpdb->prepare("UPDATE $table SET expires_at = NULL WHERE id = %d", $id));
        } else {
            $updated = $wpdb->update($table, ['expires_at' => $expires_at], ['id' => $id], ['%s'], ['%d']);
        }
        if ($updated === false) { wp_send_json_error('Bitiş süresi güncellenemedi.'); }
        CELEBI_WAF_Utils::json_success($expires_at ? 'Bitiş süresi güncellendi: ' . $expires_at : 'Kural süresiz hale getirildi.');
    }


    public function ajax_logs() {
        CELEBI_WAF_Utils::admin_check();
        CELEBI_WAF_Logger::flush();
        global $wpdb;
        $where = "WHERE 1=1";
        if (!empty($_POST['ip'])) { $where .= $wpdb->prepare(" AND ip=%s", sanitize_text_field($_POST['ip'])); }
        if (!empty($_POST['module'])) { $where .= $wpdb->prepare(" AND module=%s", sanitize_text_field($_POST['module'])); }
        CELEBI_WAF_Utils::json_success($wpdb->get_results("SELECT * FROM " . CELEBI_WAF_DB::events_table() . " $where ORDER BY id DESC LIMIT 200", ARRAY_A));
    }

    public function ajax_clear_logs() {
        CELEBI_WAF_Utils::admin_check();
        global $wpdb;
        $wpdb->query("TRUNCATE TABLE " . CELEBI_WAF_DB::events_table());
        delete_transient('celebi_waf_log_queue');
        CELEBI_WAF_Utils::json_success('Loglar temizlendi.');
    }

    public function ajax_save_settings() {
        CELEBI_WAF_Utils::admin_check();
        update_option('celebi_waf_enabled', !empty($_POST['enabled']) ? '1' : '0');
        update_option('celebi_waf_sampling_rate', max(1, min(100, intval($_POST['sampling_rate'] ?? 100))));
        update_option('celebi_waf_rate_limit', max(10, intval($_POST['rate_limit'] ?? 120)));
        update_option('celebi_waf_auto_challenge', !empty($_POST['auto_challenge']) ? '1' : '0');
        update_option('celebi_waf_challenge_enabled', !empty($_POST['challenge_enabled']) ? '1' : '0');
        update_option('celebi_waf_challenge_ttl', max(5, intval($_POST['challenge_ttl'] ?? 60)));
        update_option('celebi_waf_geo_enabled', !empty($_POST['geo_enabled']) ? '1' : '0');
        CELEBI_WAF_Utils::json_success('Ayarlar kaydedildi.');
    }


    public function ajax_save_enterprise() {
        CELEBI_WAF_Utils::admin_check();
        update_option('celebi_waf_saas_enabled', !empty($_POST['saas_enabled']) ? '1' : '0');
        update_option('celebi_waf_saas_api_url', CELEBI_WAF_Utils::safe_remote_url(wp_unslash($_POST['saas_api_url'] ?? '')));
        update_option('celebi_waf_saas_api_key', sanitize_text_field($_POST['saas_api_key'] ?? ''));
        update_option('celebi_waf_saas_site_id', sanitize_text_field($_POST['saas_site_id'] ?? ''));
        update_option('celebi_waf_threat_intel_enabled', !empty($_POST['threat_enabled']) ? '1' : '0');
        update_option('celebi_waf_threat_feed_url', CELEBI_WAF_Utils::safe_remote_url(wp_unslash($_POST['threat_feed_url'] ?? '')));
        update_option('celebi_waf_edge_enabled', !empty($_POST['edge_enabled']) ? '1' : '0');
        update_option('celebi_waf_bot_ai_enabled', !empty($_POST['bot_ai_enabled']) ? '1' : '0');
        update_option('celebi_waf_bot_ai_threshold', max(30, min(100, intval($_POST['bot_ai_threshold'] ?? 75))));
        CELEBI_WAF_Utils::json_success('Enterprise ayarları kaydedildi.');
    }


    public function ajax_save_bot_ai() {
        CELEBI_WAF_Utils::admin_check();
        update_option('celebi_waf_bot_ai_enabled', !empty($_POST['enabled']) ? '1' : '0');
        update_option('celebi_waf_bot_ai_threshold', max(30, min(100, intval($_POST['threshold'] ?? 75))));
        update_option('celebi_waf_bot_ai_endpoints', sanitize_textarea_field(wp_unslash($_POST['endpoints'] ?? '')));
        update_option('celebi_waf_bot_ai_signatures', sanitize_textarea_field(wp_unslash($_POST['signatures'] ?? '')));
        CELEBI_WAF_Utils::json_success('Bot AI ayarları kaydedildi.');
    }


    public function ajax_save_threat_intel() {
        CELEBI_WAF_Utils::admin_check();
        update_option('celebi_waf_threat_intel_enabled', !empty($_POST['enabled']) ? '1' : '0');
        update_option('celebi_waf_threat_feed_url', CELEBI_WAF_Utils::safe_remote_url(wp_unslash($_POST['feed_url'] ?? '')));
        $challenge = max(10, min(100, intval($_POST['challenge_threshold'] ?? 70)));
        $block = max($challenge, min(100, intval($_POST['block_threshold'] ?? 90)));
        update_option('celebi_waf_threat_challenge_threshold', $challenge);
        update_option('celebi_waf_threat_block_threshold', $block);
        update_option('celebi_waf_threat_cache_ttl', max(5, min(1440, intval($_POST['cache_ttl'] ?? 360))));
        update_option('celebi_waf_threat_bad_prefixes', sanitize_textarea_field(wp_unslash($_POST['prefixes'] ?? '')));
        CELEBI_WAF_Utils::json_success('Threat Intelligence ayarları kaydedildi.');
    }

    public function ajax_test_threat_intel() {
        CELEBI_WAF_Utils::admin_check();
        $ip = CELEBI_WAF_Utils::ip();
        $rep = CELEBI_WAF_Module_Threat_Intel::reputation($ip);
        CELEBI_WAF_Utils::json_success(['ip'=>$ip, 'score'=>$rep['score'], 'source'=>$rep['source']]);
    }

    private function default_update_manifest_url() {
        return 'https://github.com/celebisg/celebiwaf.git';
    }

    private function raw_update_manifest_url() {
        return 'https://raw.githubusercontent.com/celebisg/celebiwaf/main/celebi-waf-manifest.json';
    }

    private function github_repo_zip_url() {
        return 'https://github.com/celebisg/celebiwaf/archive/refs/heads/main.zip';
    }

    private function normalize_manifest_url($url) {
        $url = trim((string) $url);
        if ($url === '' || $url === 'https://github.com/celebisg/celebiwaf.git' || $url === 'https://github.com/celebisg/celebiwaf') {
            return $this->raw_update_manifest_url();
        }
        if (preg_match('#^https://github\.com/([^/]+)/([^/.]+)(?:\.git)?/?$#i', $url, $m)) {
            return 'https://raw.githubusercontent.com/' . sanitize_key($m[1]) . '/' . sanitize_key($m[2]) . '/main/celebi-waf-manifest.json';
        }
        return CELEBI_WAF_Utils::safe_remote_url($url);
    }

    private function display_manifest_url() {
        return get_option('celebi_waf_update_manifest_url', $this->default_update_manifest_url());
    }

    private function read_update_manifest() {
        $saved_url = get_option('celebi_waf_update_manifest_url', $this->default_update_manifest_url());
        $url = $this->normalize_manifest_url($saved_url);
        if (!$url) { return new WP_Error('celebi_manifest_url', 'Manifest URL geçersiz.'); }
        $request_url = add_query_arg('cwaf_cache_bust', time(), $url);
        $response = wp_remote_get($request_url, [
            'timeout' => 20,
            'redirection' => 5,
            'limit_response_size' => 1048576,
            'headers' => [
                'Accept' => 'application/json,text/plain,*/*',
                'Cache-Control' => 'no-cache',
                'Pragma' => 'no-cache',
                'User-Agent' => 'CELEBI-WAF-Updater/' . CELEBI_WAF_VERSION . '; ' . home_url('/')
            ]
        ]);
        if (is_wp_error($response)) { return $response; }
        $code = intval(wp_remote_retrieve_response_code($response));
        if ($code < 200 || $code >= 300) { return new WP_Error('celebi_manifest_http', 'Manifest HTTP yanıt kodu: ' . $code . ' URL: ' . $url); }
        $body = trim(wp_remote_retrieve_body($response));
        $json = json_decode($body, true);
        if (!is_array($json) || empty($json['version'])) {
            return new WP_Error('celebi_manifest_format', 'Manifest formatı geçersiz veya version alanı yok. İlk 120 karakter: ' . substr(wp_strip_all_tags($body), 0, 120));
        }
        $json['name'] = sanitize_text_field($json['name'] ?? 'CELEBI WAF');
        $json['slug'] = sanitize_key($json['slug'] ?? 'celebi-waf');
        $json['version'] = sanitize_text_field($json['version']);
        $json['manifest_url'] = !empty($json['manifest_url']) ? CELEBI_WAF_Utils::safe_remote_url($json['manifest_url']) : $url;
        $json['download_url'] = !empty($json['download_url']) ? CELEBI_WAF_Utils::safe_remote_url($json['download_url']) : $this->github_repo_zip_url();
        $json['package_url'] = !empty($json['package_url']) ? CELEBI_WAF_Utils::safe_remote_url($json['package_url']) : $json['download_url'];
        $json['repo_url'] = !empty($json['repo_url']) ? esc_url_raw($json['repo_url']) : 'https://github.com/celebisg/celebiwaf.git';
        $json['requires_php'] = sanitize_text_field($json['requires_php'] ?? '7.4');
        $json['requires_wp'] = sanitize_text_field($json['requires_wp'] ?? '5.8');
        $json['tested_wp'] = sanitize_text_field($json['tested_wp'] ?? '6.5');
        $json['release_date'] = sanitize_text_field($json['release_date'] ?? current_time('Y-m-d'));
        $json['changelog'] = isset($json['changelog']) && is_array($json['changelog']) ? array_map('sanitize_text_field', $json['changelog']) : [];
        return $json;
    }

    public function get_update_status($silent = false) {
        $current = CELEBI_WAF_VERSION;
        $json = $this->read_update_manifest();
        if (is_wp_error($json)) { return $json; }
        $latest = $json['version'];
        return [
            'current' => $current,
            'latest' => $latest,
            'update_available' => version_compare($latest, $current, '>'),
            'repo_url' => $json['repo_url'],
            'manifest_url' => $this->display_manifest_url(),
            'effective_manifest_url' => $json['manifest_url'],
            'download_url' => $json['download_url'],
            'package_url' => $json['package_url'],
            'requires_php' => $json['requires_php'],
            'requires_wp' => $json['requires_wp'],
            'tested_wp' => $json['tested_wp'],
            'release_date' => $json['release_date'],
            'changelog' => $json['changelog']
        ];
    }

    public function ajax_save_version_manifest() {
        CELEBI_WAF_Utils::admin_check();
        $url = $this->normalize_manifest_url(wp_unslash($_POST['manifest_url'] ?? ''));
        if (!$url) { $url = $this->default_update_manifest_url(); }
        update_option('celebi_waf_update_manifest_url', trim((string) wp_unslash($_POST['manifest_url'] ?? $this->default_update_manifest_url())));
        CELEBI_WAF_Utils::json_success('Manifest URL kaydedildi. Etkin raw manifest: ' . $url);
    }

    public function ajax_check_version_update() {
        CELEBI_WAF_Utils::admin_check();
        $status = $this->get_update_status();
        if (is_wp_error($status)) { wp_send_json_error($status->get_error_message()); }
        CELEBI_WAF_Utils::json_success($status);
    }

    public function ajax_install_version_update() {
        CELEBI_WAF_Utils::admin_check();
        if (!current_user_can('update_plugins')) { wp_send_json_error('Güncelleme için update_plugins yetkisi gerekli.'); }
        $json = $this->read_update_manifest();
        if (is_wp_error($json)) { wp_send_json_error($json->get_error_message()); }
        if (!version_compare($json['version'], CELEBI_WAF_VERSION, '>')) { wp_send_json_error('Kurulu sürüm zaten güncel.'); }
        if (version_compare(PHP_VERSION, $json['requires_php'], '<')) { wp_send_json_error('PHP sürümü yetersiz. Gerekli: ' . $json['requires_php']); }
        if (version_compare(get_bloginfo('version'), $json['requires_wp'], '<')) { wp_send_json_error('WordPress sürümü yetersiz. Gerekli: ' . $json['requires_wp']); }
        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        $package = CELEBI_WAF_Utils::safe_remote_url($json['package_url']);
        if (!$package) { wp_send_json_error('Paket URL geçersiz.'); }
        $tmp = download_url($package, 30);
        if (is_wp_error($tmp)) { wp_send_json_error('Paket indirilemedi: ' . $tmp->get_error_message()); }
        $upgrade_dir = trailingslashit(WP_CONTENT_DIR) . 'upgrade/celebi-waf-' . time();
        if (!wp_mkdir_p($upgrade_dir) || !is_dir($upgrade_dir) || !is_writable($upgrade_dir)) {
            @unlink($tmp);
            wp_send_json_error('Geçici güncelleme klasörü yazılabilir değil: ' . $upgrade_dir);
        }

        $unzipped = $this->extract_zip_without_wp_filesystem($tmp, $upgrade_dir);
        @unlink($tmp);
        if (is_wp_error($unzipped)) { wp_send_json_error('Paket açılamadı: ' . $unzipped->get_error_message()); }

        $plugin_file = $this->find_plugin_file($upgrade_dir);
        if (!$plugin_file || !is_readable($plugin_file)) { wp_send_json_error('Paket içinde celebi-waf.php bulunamadı. Paket URL GitHub main.zip veya eklenti ZIP dosyası olmalıdır.'); }
        $headers = get_file_data($plugin_file, ['Plugin Name'=>'Plugin Name', 'Version'=>'Version']);
        if (stripos($headers['Plugin Name'], 'CELEBI WAF') === false) { wp_send_json_error('Paket doğrulaması başarısız: Plugin Name eşleşmedi.'); }
        if (!empty($headers['Version']) && version_compare($headers['Version'], CELEBI_WAF_VERSION, '<=')) { wp_send_json_error('Paket sürümü kurulu sürümden yeni değil.'); }

        $source_dir = trailingslashit(dirname($plugin_file));
        $dest_dir = CELEBI_WAF_PATH;
        if (!is_dir($dest_dir) || !is_writable($dest_dir)) { wp_send_json_error('Eklenti klasörü yazılabilir değil: ' . $dest_dir . ' Sunucuda dosya izinlerini veya sahipliği kontrol edin.'); }
        $copied = $this->recursive_copy_update($source_dir, $dest_dir, ['.git', '.github', 'node_modules']);
        if (is_wp_error($copied)) { wp_send_json_error('Dosyalar kopyalanamadı: ' . $copied->get_error_message()); }
        delete_site_transient('update_plugins');
        CELEBI_WAF_Utils::json_success('Güncelleme başarıyla yüklendi. Yeni sürüm: ' . $json['version'] . '. Sayfayı yenileyip sürümü tekrar kontrol edebilirsiniz.');
    }


    private function extract_zip_without_wp_filesystem($zip_file, $destination) {
        if (class_exists('ZipArchive')) {
            $zip = new ZipArchive();
            $opened = $zip->open($zip_file);
            if ($opened === true) {
                $ok = $zip->extractTo($destination);
                $zip->close();
                return $ok ? true : new WP_Error('celebi_zip_extract', 'ZipArchive paketi açamadı.');
            }
        }
        require_once ABSPATH . 'wp-admin/includes/file.php';
        global $wp_filesystem;
        if (!$wp_filesystem) {
            WP_Filesystem(false, WP_CONTENT_DIR, true);
        }
        return unzip_file($zip_file, $destination);
    }

    private function find_plugin_file($base_dir) {
        $base_dir = untrailingslashit($base_dir);
        $direct = $base_dir . '/celebi-waf.php';
        if (is_readable($direct)) { return $direct; }
        $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base_dir, FilesystemIterator::SKIP_DOTS));
        foreach ($rii as $file) {
            if ($file->isFile() && $file->getFilename() === 'celebi-waf.php') {
                return $file->getPathname();
            }
        }
        return false;
    }

    private function recursive_copy_update($source, $destination, $exclude = []) {
        $source = trailingslashit($source);
        $destination = trailingslashit($destination);
        $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
        foreach ($rii as $item) {
            $name = $item->getFilename();
            if (in_array($name, $exclude, true)) { continue; }
            $relative = substr($item->getPathname(), strlen($source));
            $target = $destination . $relative;
            if ($item->isDir()) {
                if (!is_dir($target) && !wp_mkdir_p($target)) {
                    return new WP_Error('celebi_copy_mkdir', 'Klasör oluşturulamadı: ' . $target);
                }
            } else {
                $parent = dirname($target);
                if (!is_dir($parent) && !wp_mkdir_p($parent)) {
                    return new WP_Error('celebi_copy_parent', 'Hedef klasör oluşturulamadı: ' . $parent);
                }
                if (!@copy($item->getPathname(), $target)) {
                    return new WP_Error('celebi_copy_file', 'Dosya kopyalanamadı: ' . $relative);
                }
                @chmod($target, 0644);
            }
        }
        return true;
    }

    public function ajax_saas_test() {
        CELEBI_WAF_Utils::admin_check();
        CELEBI_WAF_Utils::json_success(CELEBI_WAF_Module_SaaS::heartbeat());
    }

    public function ajax_edge_rules() {
        CELEBI_WAF_Utils::admin_check();
        CELEBI_WAF_Utils::json_success([
            'rules' => CELEBI_WAF_Module_Edge::nginx_rules(),
            'file' => CELEBI_WAF_Module_Edge::export_file()
        ]);
    }

}
