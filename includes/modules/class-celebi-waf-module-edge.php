<?php
if (!defined('ABSPATH')) { exit; }

class CELEBI_WAF_Module_Edge {
    public static function nginx_rules() {
        $rules = [
            "# CELEBI WAF v4 Enterprise - Nginx Edge-Level önerilen kurallar",
            "# Bu çıktıyı sunucu yöneticiniz nginx server/location bloğuna kontrollü şekilde eklemelidir.",
            "set \$celebi_waf_block 0;",
            "",
            "# SQL Injection temel pattern",
            "if (\$query_string ~* \"(union.*select|or.*1=1|information_schema|sleep\\(|benchmark\\()\") { set \$celebi_waf_block 1; }",
            "",
            "# XSS temel pattern",
            "if (\$query_string ~* \"(<script|javascript:|onerror=|onload=)\") { set \$celebi_waf_block 1; }",
            "",
            "# Kötü bot araçları",
            "if (\$http_user_agent ~* \"(sqlmap|nikto|acunetix|masscan|zgrab|python-requests)\") { set \$celebi_waf_block 1; }",
            "",
            "# Path traversal",
            "if (\$request_uri ~* \"(\\.\\./|/etc/passwd|boot\\.ini)\") { set \$celebi_waf_block 1; }",
            "",
            "if (\$celebi_waf_block = 1) { return 403; }",
            "",
            "# Basit rate limit örneği - http bloğunda tanımlayın:",
            "# limit_req_zone \$binary_remote_addr zone=celebiwaf:10m rate=10r/s;",
            "# location / { limit_req zone=celebiwaf burst=30 nodelay; }"
        ];
        return implode("\n", $rules);
    }

    public static function export_file() {
        $upload = wp_upload_dir();
        $dir = trailingslashit($upload['basedir']) . 'celebi-waf';
        wp_mkdir_p($dir);
        $file = $dir . '/nginx-celebi-waf.conf';
        file_put_contents($file, self::nginx_rules());
        return $file;
    }
}
