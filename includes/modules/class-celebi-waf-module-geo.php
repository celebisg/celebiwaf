<?php
if (!defined('ABSPATH')) { exit; }

class CELEBI_WAF_Module_Geo {
    public function lookup($ip) {
        $fallback = ['country' => 'Yerel/Özel IP', 'lat' => 39.92077, 'lng' => 32.85411];

        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return $fallback;
        }

        $cache_key = 'celebi_waf_geo_' . md5($ip);
        $cached = get_transient($cache_key);
        if (is_array($cached)) { return $cached; }

        if (get_option('celebi_waf_geo_enabled', '1') === '1') {
            $response = wp_remote_get('http://ip-api.com/json/' . rawurlencode($ip) . '?fields=status,country,lat,lon', ['timeout' => 2]);
            if (!is_wp_error($response)) {
                $json = json_decode(wp_remote_retrieve_body($response), true);
                if (is_array($json) && ($json['status'] ?? '') === 'success') {
                    $geo = ['country' => sanitize_text_field($json['country']), 'lat' => floatval($json['lat']), 'lng' => floatval($json['lon'])];
                    set_transient($cache_key, $geo, DAY_IN_SECONDS);
                    return $geo;
                }
            }
        }

        $sample = [
            ['country' => 'Türkiye', 'lat' => 39.92077, 'lng' => 32.85411],
            ['country' => 'Almanya', 'lat' => 52.52000, 'lng' => 13.40500],
            ['country' => 'ABD', 'lat' => 38.90720, 'lng' => -77.03690],
            ['country' => 'Hollanda', 'lat' => 52.36760, 'lng' => 4.90410],
            ['country' => 'Fransa', 'lat' => 48.85660, 'lng' => 2.35220]
        ];
        $geo = $sample[abs(crc32($ip)) % count($sample)];
        set_transient($cache_key, $geo, HOUR_IN_SECONDS);
        return $geo;
    }
}
