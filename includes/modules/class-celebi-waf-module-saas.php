<?php
if (!defined('ABSPATH')) { exit; }

class CELEBI_WAF_Module_SaaS {
    public static function enabled() { return get_option('celebi_waf_saas_enabled', '0') === '1'; }

    public static function push_event($event) {
        if (!self::enabled()) { return false; }
        $url = CELEBI_WAF_Utils::safe_remote_url(get_option('celebi_waf_saas_api_url', ''));
        $key = trim(get_option('celebi_waf_saas_api_key', ''));
        $site = trim(get_option('celebi_waf_saas_site_id', ''));
        if (!$url || !$key || !$site) { return false; }

        $response = wp_remote_post(rtrim($url, '/') . '/api/v1/events', [
            'timeout' => 5,
            'headers' => [
                'Content-Type' => 'application/json',
                'X-CELEBI-WAF-KEY' => $key,
                'X-CELEBI-WAF-SITE' => $site
            ],
            'body' => wp_json_encode($event)
        ]);
        return !is_wp_error($response);
    }

    public static function heartbeat() {
        if (!self::enabled()) { return ['success'=>false, 'message'=>'Merkezi panel pasif.']; }
        $url = CELEBI_WAF_Utils::safe_remote_url(get_option('celebi_waf_saas_api_url', ''));
        $key = trim(get_option('celebi_waf_saas_api_key', ''));
        $site = trim(get_option('celebi_waf_saas_site_id', ''));
        if (!$url || !$key || !$site) { return ['success'=>false, 'message'=>'API URL, API Key veya Site ID eksik.']; }

        $response = wp_remote_post(rtrim($url, '/') . '/api/v1/heartbeat', [
            'timeout' => 8,
            'headers' => [
                'Content-Type' => 'application/json',
                'X-CELEBI-WAF-KEY' => $key,
                'X-CELEBI-WAF-SITE' => $site
            ],
            'body' => wp_json_encode([
                'site_url' => home_url(),
                'wp_version' => get_bloginfo('version'),
                'plugin_version' => CELEBI_WAF_VERSION,
                'time' => current_time('mysql')
            ])
        ]);
        if (is_wp_error($response)) { return ['success'=>false, 'message'=>$response->get_error_message()]; }
        return ['success'=>true, 'message'=>'Merkezi panel bağlantısı başarılı.', 'response'=>json_decode(wp_remote_retrieve_body($response), true)];
    }

    public static function api_server_template() {
        return <<<'PHP'
<?php
/**
 * CELEBI WAF Merkezi API Server - Örnek PHP Endpoint
 * Bunu ayrı bir domain/API projesinde kullanın. WordPress eklentisinin içinde çalıştırmayın.
 */
header('Content-Type: application/json');

$validKey = getenv('CELEBI_WAF_MASTER_KEY') ?: 'CHANGE_ME_MASTER_KEY';
$key = $_SERVER['HTTP_X_CELEBI_WAF_KEY'] ?? '';
$site = $_SERVER['HTTP_X_CELEBI_WAF_SITE'] ?? '';

if (!hash_equals($validKey, $key) || !$site) {
    http_response_code(401);
    echo json_encode(['success'=>false,'message'=>'Unauthorized']);
    exit;
}

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$body = json_decode(file_get_contents('php://input'), true) ?: [];

if (str_ends_with($path, '/api/v1/heartbeat')) {
    echo json_encode(['success'=>true,'message'=>'heartbeat ok','site'=>$site,'server_time'=>date('c')]);
    exit;
}

if (str_ends_with($path, '/api/v1/events')) {
    // Production için DB’ye yazın: site_id, ip, module, risk_score, action, created_at.
    file_put_contents(__DIR__.'/events.log', json_encode(['site'=>$site,'event'=>$body,'time'=>date('c')]).PHP_EOL, FILE_APPEND);
    echo json_encode(['success'=>true,'message'=>'event accepted']);
    exit;
}

http_response_code(404);
echo json_encode(['success'=>false,'message'=>'not found']);
PHP;
    }
}
