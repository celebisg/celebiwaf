<?php
/**
 * Plugin Name: CELEBI WAF
 * Description: Modüler profesyonel WordPress WAF: dinamik kural motoru, bot analizi, IP challenge, rate limit, geo lookup, async loglama ve gelişmiş dashboard.
 * Version: 1.0.6
 * Author: CELEBI
 * Text Domain: celebi-waf
 */

if (!defined('ABSPATH')) { exit; }

define('CELEBI_WAF_VERSION', '1.0.6');
define('CELEBI_WAF_PATH', plugin_dir_path(__FILE__));
define('CELEBI_WAF_URL', plugin_dir_url(__FILE__));
define('CELEBI_WAF_TABLE_PREFIX', 'celebi_waf_');

require_once CELEBI_WAF_PATH . 'includes/class-celebi-waf-db.php';
require_once CELEBI_WAF_PATH . 'includes/class-celebi-waf-utils.php';
require_once CELEBI_WAF_PATH . 'includes/class-celebi-waf-logger.php';
require_once CELEBI_WAF_PATH . 'includes/class-celebi-waf-rules.php';
require_once CELEBI_WAF_PATH . 'includes/modules/class-celebi-waf-module-waf.php';
require_once CELEBI_WAF_PATH . 'includes/modules/class-celebi-waf-module-bot.php';
require_once CELEBI_WAF_PATH . 'includes/modules/class-celebi-waf-module-rate-limit.php';
require_once CELEBI_WAF_PATH . 'includes/modules/class-celebi-waf-module-challenge.php';
require_once CELEBI_WAF_PATH . 'includes/modules/class-celebi-waf-module-geo.php';
require_once CELEBI_WAF_PATH . 'includes/modules/class-celebi-waf-module-saas.php';
require_once CELEBI_WAF_PATH . 'includes/modules/class-celebi-waf-module-threat-intel.php';
require_once CELEBI_WAF_PATH . 'includes/modules/class-celebi-waf-module-edge.php';
require_once CELEBI_WAF_PATH . 'includes/modules/class-celebi-waf-module-bot-ai.php';
require_once CELEBI_WAF_PATH . 'includes/class-celebi-waf-core.php';
require_once CELEBI_WAF_PATH . 'admin/admin-page.php';

register_activation_hook(__FILE__, ['CELEBI_WAF_DB', 'activate']);
register_deactivation_hook(__FILE__, ['CELEBI_WAF_DB', 'deactivate']);

add_action('plugins_loaded', function () {
    CELEBI_WAF_Core::instance();
});

add_action('admin_menu', function () {
    add_menu_page('CELEBI WAF', 'CELEBI WAF', 'manage_options', 'celebi-waf', 'celebi_waf_render_dashboard', CELEBI_WAF_URL . 'assets/menu-icon.png', 58);
    
    // Genel Güvenlik Merkezi
    add_submenu_page('celebi-waf', 'Dashboard', 'Dashboard', 'manage_options', 'celebi-waf', 'celebi_waf_render_dashboard');
    add_submenu_page('celebi-waf', 'Canlı Modüller', 'Canlı Modüller', 'manage_options', 'celebi-waf-modules', 'celebi_waf_render_modules');
    add_submenu_page('celebi-waf', 'Loglar', 'Loglar & Olaylar', 'manage_options', 'celebi-waf-logs', 'celebi_waf_render_logs');

    // Koruma Yönetimi
    add_submenu_page('celebi-waf', 'IP Challenge', 'IP Challenge', 'manage_options', 'celebi-waf-challenge', 'celebi_waf_render_challenge');
    add_submenu_page('celebi-waf', 'Kural Motoru', 'Dinamik Kural Motoru', 'manage_options', 'celebi-waf-rules', 'celebi_waf_render_rules');
    add_submenu_page('celebi-waf', 'Bot AI', 'Bot AI Koruması', 'manage_options', 'celebi-waf-bot-ai', 'celebi_waf_render_bot_ai');

    // Enterprise Özellikleri
    add_submenu_page('celebi-waf', 'Enterprise Modüller', 'Enterprise Modüller', 'manage_options', 'celebi-waf-enterprise', 'celebi_waf_render_enterprise');
    add_submenu_page('celebi-waf', 'Merkezi Panel', 'Merkezi Yönetim', 'manage_options', 'celebi-waf-saas', 'celebi_waf_render_saas');
    add_submenu_page('celebi-waf', 'Threat Intelligence', 'Threat Intelligence', 'manage_options', 'celebi-waf-threat-intel', 'celebi_waf_render_threat_intel');
    add_submenu_page('celebi-waf', 'Nginx Edge-Level', 'Nginx Edge-Level', 'manage_options', 'celebi-waf-edge', 'celebi_waf_render_edge');

    // Sistem
    add_submenu_page('celebi-waf', 'Ayarlar', 'Ayarlar', 'manage_options', 'celebi-waf-settings', 'celebi_waf_render_settings');
    add_submenu_page('celebi-waf', 'Sürüm Güncellemesi', 'Sürüm Güncellemesi', 'manage_options', 'celebi-waf-version-update', 'celebi_waf_render_version_update');
    add_submenu_page('celebi-waf', 'Doküman', 'Dokümantasyon', 'manage_options', 'celebi-waf-docs', 'celebi_waf_render_docs');
});

add_action('admin_enqueue_scripts', function ($hook) {
    if (strpos($hook, 'celebi-waf') === false) { return; }
    wp_enqueue_style('celebi-waf-admin', CELEBI_WAF_URL . 'assets/admin.css', [], CELEBI_WAF_VERSION);
    wp_enqueue_script('chart-js', 'https://cdn.jsdelivr.net/npm/chart.js', [], '4.4.1', true);
    wp_enqueue_script('leaflet-js', 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js', [], '1.9.4', true);
    wp_enqueue_style('leaflet-css', 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css', [], '1.9.4');
    wp_enqueue_script('celebi-waf-admin', CELEBI_WAF_URL . 'assets/admin.js', ['jquery', 'chart-js', 'leaflet-js'], CELEBI_WAF_VERSION, true);
    wp_localize_script('celebi-waf-admin', 'CELEBIWAF', [
        'ajax' => admin_url('admin-ajax.php'),
        'nonce' => wp_create_nonce('celebi_waf_nonce')
    ]);
});


add_action('admin_notices', function () {
    if (!current_user_can('manage_options')) { return; }
    if (!class_exists('CELEBI_WAF_Core')) { return; }
    $screen = function_exists('get_current_screen') ? get_current_screen() : null;
    if (!$screen || strpos($screen->id, 'celebi-waf') === false) { return; }
    $check = CELEBI_WAF_Core::instance()->get_update_status(true);
    if (is_wp_error($check) || empty($check['update_available'])) { return; }
    $url = admin_url('admin.php?page=celebi-waf-version-update');
    echo '<div class="notice notice-warning is-dismissible"><p><strong>CELEBI WAF:</strong> Yeni sürüm mevcut: ' . esc_html($check['latest']) . ' <a href="' . esc_url($url) . '">Sürüm Güncellemesi ekranına git</a></p></div>';
});
