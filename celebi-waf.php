<?php
/**
 * Plugin Name: CELEBI WAF
 * Description: CELEBI WAF v1.2.0 - Modüler WordPress WAF, Threat Intelligence, Bot AI, IP Challenge ve YENİ: Yapay Zeka Destekli Anomali Tespiti & Akıllı Raporlama.
 * Version: 1.2.0
 * Author: CELEBI
 * Text Domain: celebi-waf
 */

if (!defined('ABSPATH')) { exit; }

define('CELEBI_WAF_VERSION', '1.2.0');
define('CELEBI_WAF_PATH', plugin_dir_path(__FILE__));
define('CELEBI_WAF_URL', plugin_dir_url(__FILE__));
define('CELEBI_WAF_TABLE_PREFIX', 'celebi_waf_');

// Mevcut Core Dosyaları (Varsayılan yapı)
// require_once CELEBI_WAF_PATH . 'includes/class-celebi-waf-db.php';
// require_once CELEBI_WAF_PATH . 'includes/class-celebi-waf-utils.php';

// YENİ: Yapay Zeka Motoru Entegrasyonu
require_once CELEBI_WAF_PATH . 'includes/class-celebi-waf-ai-core.php';

// AI Core Başlatma
add_action('plugins_loaded', function() {
    if (class_exists('CELEBI_WAF_AI_Core')) {
        global $celebi_waf_ai;
        $celebi_waf_ai = new CELEBI_WAF_AI_Core();
    }
});
