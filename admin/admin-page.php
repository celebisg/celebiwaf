<?php
if (!defined('ABSPATH')) { exit; }

function celebi_waf_logo_html() {
    $logo = esc_url(CELEBI_WAF_URL . 'assets/admin-logo.png');
    return '<img class="celebi-waf-logo" src="' . $logo . '" alt="CELEBI WAF">';
}
function celebi_waf_header($title, $desc) { ?>
    <div class="celebi-waf-header"><?php echo celebi_waf_logo_html(); ?><div><h1><?php echo esc_html($title); ?></h1><p class="celebi-waf-muted"><?php echo esc_html($desc); ?></p></div></div>
<?php }



function celebi_waf_count_table_safe($table, $where = '') {
    global $wpdb;
    $exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table));
    if ($exists !== $table) { return 0; }
    $sql = "SELECT COUNT(*) FROM {$table}" . ($where ? " WHERE {$where}" : '');
    return intval($wpdb->get_var($sql));
}

function celebi_waf_dashboard_snapshot() {
    if (class_exists('CELEBI_WAF_DB')) { CELEBI_WAF_DB::maybe_upgrade(); }
    if (class_exists('CELEBI_WAF_Logger')) { CELEBI_WAF_Logger::flush(); }
    global $wpdb;
    $events = CELEBI_WAF_DB::events_table();
    $rules = CELEBI_WAF_DB::rules_table();
    $ip_rules = CELEBI_WAF_DB::ip_rules_table();
    $event_exists = ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $events)) === $events);
    $rules_exists = ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $rules)) === $rules);
    $ip_exists = ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $ip_rules)) === $ip_rules);
    $count = function($sql) use ($wpdb) { $v = $wpdb->get_var($sql); return is_null($v) ? 0 : intval($v); };
    return [
        'total' => $event_exists ? $count("SELECT COUNT(*) FROM $events") : 0,
        'blocked' => $event_exists ? $count("SELECT COUNT(*) FROM $events WHERE action IN ('engellendi','challenge','block') OR risk_score >= 90") : 0,
        'last_hour' => $event_exists ? $count("SELECT COUNT(*) FROM $events WHERE event_time >= DATE_SUB(NOW(), INTERVAL 1 HOUR)") : 0,
        'bots' => $event_exists ? $count("SELECT COUNT(*) FROM $events WHERE module LIKE '%Bot%' OR attack_type LIKE '%Bot%' OR user_agent LIKE '%bot%' OR user_agent LIKE '%curl%' OR user_agent LIKE '%python%'") : 0,
        'ip_challenge' => $ip_exists ? $count("SELECT COUNT(*) FROM $ip_rules WHERE rule_type='challenge'") : 0,
        'rules' => $rules_exists ? $count("SELECT COUNT(*) FROM $rules WHERE enabled=1") : 0,
        'waf_engine' => $event_exists ? $count("SELECT COUNT(*) FROM $events WHERE module IN ('WAF Motoru','SQL Injection','XSS','Bot Engelleme','DDoS Koruma Katmanı','IP Challenge / Bot Engelleme') OR risk_score > 0") : 0,
        'sql_xss' => $event_exists ? $count("SELECT COUNT(*) FROM $events WHERE module IN ('SQL Injection','XSS') OR attack_type IN ('SQL Injection','XSS') OR attack_type LIKE '%SQL%' OR attack_type LIKE '%XSS%'") : 0,
        'ddos' => $event_exists ? $count("SELECT COUNT(*) FROM $events WHERE module='DDoS Koruma Katmanı' OR attack_type LIKE '%DDoS%' OR attack_type LIKE '%Rate%'") : 0,
        'async_queue' => intval(count(get_transient('celebi_waf_log_queue') ?: [])),
        'geo_lookup' => intval(get_option('celebi_waf_geo_enabled','1')),
    ];
}

function celebi_waf_module_snapshot() {
    $m = celebi_waf_dashboard_snapshot();
    return [
        ['name'=>'WAF Motoru', 'count'=>$m['waf_engine'], 'status'=>'Aktif', 'class'=>'waf-engine'],
        ['name'=>'Gerçek Zamanlı Trafik İzleme', 'count'=>$m['total'], 'status'=>'Aktif', 'class'=>'traffic-monitor'],
        ['name'=>'SQL Injection ve XSS Analizi', 'count'=>$m['sql_xss'], 'status'=>'Aktif', 'class'=>'sql-xss'],
        ['name'=>'Bot Engelleme', 'count'=>$m['bots'], 'status'=>'Aktif', 'class'=>'bot-block'],
        ['name'=>'DDoS Koruma Katmanı', 'count'=>$m['ddos'] ?: $m['blocked'], 'status'=>'Aktif', 'class'=>'ddos-layer'],
        ['name'=>'IP Challenge Dinamik Kural Motoru', 'count'=>$m['ip_challenge'], 'status'=>get_option('celebi_waf_challenge_enabled','1')==='1'?'Aktif':'Pasif', 'class'=>'ip-challenge'],
        ['name'=>'Dinamik Kural Motoru', 'count'=>$m['rules'], 'status'=>'Aktif', 'class'=>'rule-engine'],
        ['name'=>'Async Loglama', 'count'=>$m['async_queue'], 'status'=>'Aktif', 'class'=>'async-log'],
        ['name'=>'Gerçek Geo Lookup', 'count'=>$m['geo_lookup'], 'status'=>get_option('celebi_waf_geo_enabled','1')==='1'?'Aktif':'Pasif', 'class'=>'geo-lookup'],
    ];
}

function celebi_waf_bot_ai_snapshot() {
    $m = celebi_waf_dashboard_snapshot();
    $threshold = intval(get_option('celebi_waf_bot_ai_threshold',75));
    $score = min(100, max(0, $m['bots'] ? ($threshold + 10) : 25));
    $action = $score >= $threshold ? 'Challenge / Block' : 'İzle';
    return [
        'threshold' => $threshold,
        'requests' => $m['total'],
        'fingerprint' => $m['bots'] . ' şüpheli iz',
        'score' => $score,
        'action' => $action,
    ];
}

function celebi_waf_threat_reputation_snapshot() {
    $raw = get_option('celebi_waf_threat_manual_reputation', '');
    $rows = json_decode((string) $raw, true);
    if (!is_array($rows) || empty($rows)) {
        $rows = [
            ['ip'=>'198.51.100.24','feed'=>'Demo Reputation Feed','score'=>72,'action'=>'challenge','note'=>'Örnek orta risk kaydı','updated_at'=>current_time('mysql')],
            ['ip'=>'203.0.113.44','feed'=>'Demo Abuse Feed','score'=>94,'action'=>'block','note'=>'Örnek yüksek risk kaydı','updated_at'=>current_time('mysql')],
            ['ip'=>'192.0.2.15','feed'=>'Local SOC Watchlist','score'=>48,'action'=>'monitor','note'=>'Örnek izleme kaydı','updated_at'=>current_time('mysql')],
        ];
        update_option('celebi_waf_threat_manual_reputation', wp_json_encode($rows), false);
    }
    $clean = [];
    foreach ((array) $rows as $row) {
        $ip = sanitize_text_field($row['ip'] ?? '');
        if (!filter_var($ip, FILTER_VALIDATE_IP)) { continue; }
        $score = max(0, min(100, intval($row['score'] ?? $row['reputation'] ?? 0)));
        $action = sanitize_key($row['action'] ?? 'monitor');
        if (!in_array($action, ['allow','monitor','challenge','block'], true)) { $action = 'monitor'; }
        $clean[] = [
            'ip' => $ip,
            'feed' => sanitize_text_field($row['feed'] ?? 'Manual SOC'),
            'reputation' => $score,
            'action' => $action,
            'source' => 'Manuel / SOC',
            'note' => sanitize_text_field($row['note'] ?? ''),
            'updated_at' => sanitize_text_field($row['updated_at'] ?? current_time('mysql')),
            'editable' => true,
        ];
    }
    usort($clean, function($a,$b){ return intval($b['reputation']) <=> intval($a['reputation']); });
    return $clean;
}

function celebi_waf_render_threat_reputation_rows() {
    $rows = celebi_waf_threat_reputation_snapshot();
    if (empty($rows)) {
        echo '<tr><td colspan="7">Henüz kayıt yok.</td></tr>';
        return;
    }
    foreach ($rows as $x) {
        echo '<tr>';
        echo '<td>' . esc_html($x['ip']) . '</td>';
        echo '<td>' . esc_html($x['feed']) . '</td>';
        echo '<td><strong>' . esc_html($x['reputation']) . '</strong></td>';
        echo '<td><span class="pill ' . esc_attr($x['action']) . '">' . esc_html($x['action']) . '</span></td>';
        echo '<td>' . esc_html($x['source']) . '</td>';
        echo '<td>' . esc_html($x['updated_at']) . '</td>';
        echo '<td><button class="button edit-threat-reputation" data-row=\'' . esc_attr(wp_json_encode($x)) . '\'>Düzenle</button> <button class="button delete-threat-reputation" data-ip="' . esc_attr($x['ip']) . '">Sil</button></td>';
        echo '</tr>';
    }
}
function celebi_waf_update_banner_inline() {
    if (!current_user_can('manage_options') || !class_exists('CELEBI_WAF_Core')) { return; }
    $status = CELEBI_WAF_Core::instance()->get_update_status(true);
    if (is_wp_error($status) || empty($status['update_available'])) { return; }
    $url = admin_url('admin.php?page=celebi-waf-version-update');
    echo '<div class="celebi-update-banner"><div><strong>Yeni Sürüm Bulundu</strong><span>Kurulu sürüm: ' . esc_html($status['current']) . ' | Son sürüm: ' . esc_html($status['latest']) . '</span></div><a class="button button-primary" href="' . esc_url($url) . '">Sürüm Güncellemesi Sekmesine Git</a></div>';
}

function celebi_waf_render_dashboard() { $cards = celebi_waf_dashboard_snapshot(); ?>
<div class="wrap celebi-waf-wrap">
<?php celebi_waf_header('CELEBI WAF v' . CELEBI_WAF_VERSION, 'Yeni nesil gerçek zamanlı tehdit analizi, gelişmiş modül yönetimi ve canlı güvenlik merkezi.'); celebi_waf_update_banner_inline(); ?>
<div class="celebi-waf-actions"><button class="button button-primary" id="celebi-refresh">Canlı Veriyi Yenile</button><button class="button" id="celebi-clear-logs">Logları Temizle</button><span id="celebi-status">Hazır</span><span class="celebi-live-dot">● Anlık izleme aktif</span></div>
<div class="celebi-waf-cards">
<div class="celebi-card card-total"><span>Toplam Trafik</span><strong id="card-total"><?php echo esc_html($cards['total']); ?></strong></div>
<div class="celebi-card card-blocked danger"><span>Engellenen/Challenge</span><strong id="card-blocked"><?php echo esc_html($cards['blocked']); ?></strong></div>
<div class="celebi-card card-hour"><span>Son 1 Saat</span><strong id="card-hour"><?php echo esc_html($cards['last_hour']); ?></strong></div>
<div class="celebi-card card-bots warning"><span>Bot Olayları</span><strong id="card-bots"><?php echo esc_html($cards['bots']); ?></strong></div>
<div class="celebi-card card-challenge info"><span>IP Challenge</span><strong id="card-challenge"><?php echo esc_html($cards['ip_challenge']); ?></strong></div>
<div class="celebi-card card-rules brand"><span>Aktif Kurallar</span><strong id="card-rules"><?php echo esc_html($cards['rules']); ?></strong></div>
</div>
<div class="celebi-grid">
<div class="celebi-panel"><h2>Saldırı Zaman Çizelgesi</h2><canvas id="chartTimeline"></canvas></div>
<div class="celebi-panel"><h2>Saldırı Türleri</h2><canvas id="chartTypes"></canvas></div>
<div class="celebi-panel"><h2>Top 10 Saldıran IP</h2><canvas id="chartIps"></canvas></div>
<div class="celebi-panel"><h2>En Çok Hedeflenen URL</h2><canvas id="chartUrls"></canvas></div>
<div class="celebi-panel"><h2>Ülke Bazlı Trafik</h2><canvas id="chartCountries"></canvas></div>
<div class="celebi-panel"><h2>Gerçek Zamanlı Saldırı Haritası</h2><div id="celebi-map"></div></div>
</div>
<div class="celebi-panel"><h2>Son Olaylar</h2><table class="widefat striped"><thead><tr><th>Zaman</th><th>IP</th><th>Ülke</th><th>Metod</th><th>URL</th><th>Modül</th><th>Kural</th><th>Risk</th><th>Aksiyon</th></tr></thead><tbody id="latest-events"><tr><td colspan="9">Yükleniyor...</td></tr></tbody></table></div>
</div>
<?php }

function celebi_waf_render_modules() { $modules = celebi_waf_module_snapshot(); ?>
<div class="wrap celebi-waf-wrap"><?php celebi_waf_header('Canlı Modül İstatistikleri', 'Modüler CELEBI WAF servislerinin canlı durumu.'); ?>
<div class="celebi-waf-actions"><button class="button button-primary" id="celebi-load-modules">Modülleri Yenile</button><span id="modules-status">Sunucu verisi hazır</span></div>
<div class="celebi-module-grid enhanced-module-grid" id="module-grid">
<?php foreach ($modules as $mod) : ?>
<div class="module-card <?php echo esc_attr($mod['class']); ?>"><h3><?php echo esc_html($mod['name']); ?></h3><strong><?php echo esc_html($mod['count']); ?></strong><span><?php echo esc_html($mod['status']); ?></span><ul><li>Canlı sayaç takibi</li><li>Durum ve aksiyon izleme</li><li>Dashboard ile korelasyon</li></ul></div>
<?php endforeach; ?>
</div></div>
<?php }

function celebi_waf_render_challenge() { ?>
<div class="wrap celebi-waf-wrap"><?php celebi_waf_header('IP Challenge / Bot Engelleme', 'WordPress üzerinde çalışan challenge, block ve allow IP yönetimi.'); ?>
<div class="celebi-panel"><h2>Yeni IP Kuralı</h2><table class="form-table">
<tr><th>IP</th><td><input id="ip-rule-ip" class="regular-text" placeholder="203.0.113.10"></td></tr>
<tr><th>Tip</th><td><select id="ip-rule-type"><option value="challenge">Challenge</option><option value="block">Block</option><option value="allow">Allow</option></select></td></tr>
<tr><th>Süre</th><td><input type="number" id="ip-rule-minutes" value="60"> dakika</td></tr>
<tr><th>Not</th><td><input id="ip-rule-note" class="regular-text"></td></tr>
</table><button class="button button-primary" id="save-ip-rule">Kaydet</button><div class="celebi-result" id="ip-rule-result"></div></div>
<div class="celebi-panel"><h2>Aktif IP Kuralları</h2><p class="description">Her aktif IP kuralının bitiş süresini bu listeden dakika bazlı olarak uzatabilir, kısaltabilir veya süresiz hale getirebilirsiniz.</p><button class="button" id="load-ip-rules">Yenile</button><table class="widefat striped"><thead><tr><th>IP</th><th>Tip</th><th>Not</th><th>Oluşturma</th><th>Bitiş</th><th>Bitiş Süresi Düzenle</th><th>İşlem</th></tr></thead><tbody id="ip-rules"></tbody></table></div>
</div>
<?php }

function celebi_waf_render_rules() { ?>
<div class="wrap celebi-waf-wrap"><?php celebi_waf_header('Dinamik Kural Motoru', 'Admin panelden WAF kuralı ekleyin, düzenleyin veya pasifleştirin.'); ?>
<div class="celebi-panel"><h2>Kural Ekle / Güncelle</h2><input type="hidden" id="rule-id">
<table class="form-table">
<tr><th>Kural Adı</th><td><input id="rule-name" class="regular-text"></td></tr>
<tr><th>Kategori</th><td><select id="rule-category"><option>SQL Injection</option><option>XSS</option><option>WAF Motoru</option><option>Bot Engelleme</option></select></td></tr>
<tr><th>Regex Pattern</th><td><textarea id="rule-pattern" class="large-text" rows="3"></textarea></td></tr>
<tr><th>Risk</th><td><input type="number" id="rule-risk" value="80" min="1" max="100"></td></tr>
<tr><th>Aksiyon</th><td><select id="rule-action"><option value="block">Block</option><option value="challenge">Challenge</option></select></td></tr>
<tr><th>Aktif</th><td><label><input type="checkbox" id="rule-enabled" checked> Aktif</label></td></tr>
</table><button class="button button-primary" id="save-rule">Kuralı Kaydet</button><button class="button" id="reset-rule">Temizle</button><div class="celebi-result" id="rule-result"></div></div>
<div class="celebi-panel"><h2>Kurallar</h2><button class="button" id="load-rules">Yenile</button><table class="widefat striped"><thead><tr><th>Ad</th><th>Kategori</th><th>Pattern</th><th>Risk</th><th>Aksiyon</th><th>Aktif</th><th>İşlem</th></tr></thead><tbody id="rules-table"></tbody></table></div>
</div>
<?php }

function celebi_waf_render_logs() { ?>
<div class="wrap celebi-waf-wrap"><?php celebi_waf_header('Güvenlik Logları', 'Filtrelenebilir son güvenlik olayları.'); ?>
<div class="celebi-panel"><input id="log-filter-ip" placeholder="IP filtrele"> <select id="log-filter-module"><option value="">Tüm modüller</option><option>SQL Injection</option><option>XSS</option><option>Bot Engelleme</option><option>DDoS Koruma Katmanı</option><option>IP Challenge / Bot Engelleme</option></select> <button class="button button-primary" id="load-logs">Logları Getir</button></div>
<div class="celebi-panel"><table class="widefat striped"><thead><tr><th>Zaman</th><th>IP</th><th>Ülke</th><th>URL</th><th>Modül</th><th>Kural</th><th>Risk</th><th>Aksiyon</th></tr></thead><tbody id="logs-table"></tbody></table></div></div>
<?php }

function celebi_waf_render_settings() { ?>
<div class="wrap celebi-waf-wrap"><?php celebi_waf_header('Ayarlar', 'WAF, performans, challenge ve geo lookup ayarları.'); ?>
<div class="celebi-panel"><h2>Genel Ayarlar</h2><table class="form-table">
<tr><th>WAF Aktif</th><td><label><input type="checkbox" id="set-enabled" <?php checked(get_option('celebi_waf_enabled','1'),'1'); ?>> Aktif</label></td></tr>
<tr><th>Sampling Oranı</th><td><input type="number" id="set-sampling" value="<?php echo esc_attr(get_option('celebi_waf_sampling_rate',100)); ?>"> % <span class="description">Normal trafik loglama oranı. Saldırılar her zaman loglanır.</span></td></tr>
<tr><th>Rate Limit</th><td><input type="number" id="set-rate" value="<?php echo esc_attr(get_option('celebi_waf_rate_limit',120)); ?>"> istek/dakika</td></tr>
<tr><th>Otomatik Challenge</th><td><label><input type="checkbox" id="set-auto-challenge" <?php checked(get_option('celebi_waf_auto_challenge','1'),'1'); ?>> Aktif</label></td></tr>
<tr><th>Challenge Aktif</th><td><label><input type="checkbox" id="set-challenge" <?php checked(get_option('celebi_waf_challenge_enabled','1'),'1'); ?>> Aktif</label></td></tr>
<tr><th>Challenge Süresi</th><td><input type="number" id="set-challenge-ttl" value="<?php echo esc_attr(get_option('celebi_waf_challenge_ttl',60)); ?>"> dakika</td></tr>
<tr><th>Gerçek Geo Lookup</th><td><label><input type="checkbox" id="set-geo" <?php checked(get_option('celebi_waf_geo_enabled','1'),'1'); ?>> Aktif</label></td></tr>
</table><button class="button button-primary" id="save-settings">Ayarları Kaydet</button><div class="celebi-result" id="settings-result"></div></div>
</div>
<?php }

function celebi_waf_render_version_update() { ?>
<div class="wrap celebi-waf-wrap"><?php celebi_waf_header('Sürüm Güncellemesi', 'GitHub manifest dosyasından canlı sürüm kontrolü, uyarı ve güvenli yükleme yönetimi.'); ?>
<div class="celebi-panel version-panel">
<div class="version-hero">
  <div class="version-current"><span>Kurulu Sürüm</span><strong><?php echo esc_html(CELEBI_WAF_VERSION); ?></strong><em>CELEBI WAF</em></div>
  <div class="version-health"><span id="version-health-badge" class="version-badge neutral">Kontrol bekleniyor</span><p>Manifest için GitHub repo adresi girilebilir; sistem bunu otomatik olarak raw JSON manifest adresine çevirir ve cache bypass ile okur.</p></div>
</div>
<table class="form-table">
<tr><th>GitHub Repo</th><td><input class="regular-text" value="https://github.com/celebisg/celebiwaf.git" readonly><p class="description">Eklenti paketi ve manifest bu repo yapısına göre hazırlanmıştır.</p></td></tr>
<tr><th>Manifest URL</th><td><input id="version-manifest-url" class="regular-text" value="<?php echo esc_attr(get_option('celebi_waf_update_manifest_url','https://github.com/celebisg/celebiwaf.git')); ?>" placeholder="https://github.com/celebisg/celebiwaf.git"><p class="description">Repo URL yazabilirsiniz: https://github.com/celebisg/celebiwaf.git. Sistem arka planda raw manifest adresini kullanır.</p></td></tr>
</table>
<div class="version-actions"><button class="button" id="save-version-manifest">Manifest URL Kaydet</button><button class="button button-primary" id="check-version-update">Sürümü Kontrol Et</button><button class="button button-secondary" id="install-version-update" disabled>Güncellemeyi Yükle</button></div>
<div class="celebi-result version-result" id="version-update-result">Sayfa açıldığında otomatik kontrol yapılır. Sonucu burada göreceksiniz.</div>
</div>
<div class="celebi-grid version-grid">
<div class="celebi-panel"><h2>Beklenen Manifest Formatı</h2><pre>{
  "name": "CELEBI WAF",
  "slug": "celebi-waf",
  "version": "1.0.9",
  "manifest_url": "https://raw.githubusercontent.com/celebisg/celebiwaf/main/celebi-waf-manifest.json",
  "download_url": "https://github.com/celebisg/celebiwaf/archive/refs/heads/main.zip",
  "package_url": "https://github.com/celebisg/celebiwaf/archive/refs/heads/main.zip"
}</pre></div>
<div class="celebi-panel"><h2>Kontrol Mantığı</h2><ul><li>Kurulu sürüm ile manifest içindeki version karşılaştırılır.</li><li>Manifest sürümü daha yüksekse uyarı ve yükleme butonu aktif olur.</li><li>Yanıtlar cache bypass parametresiyle alınır.</li><li>Paket içinde celebi-waf.php ve Plugin Name doğrulanır.</li></ul></div>
</div>
</div>
<?php }

function celebi_waf_render_docs() { ?>
<div class="wrap celebi-waf-wrap"><?php celebi_waf_header('Doküman', 'CELEBI WAF v1.0 çalışma mantığı, güvenlik mimarisi ve profesyonel kullanım önerileri.'); ?>
<div class="celebi-panel"><h2>Mimari</h2><p>v4.5 Enterprise sürümü tamamen modernize edilmiş modüler mimari ile yeniden tasarlanmıştır. Core sınıfı istek bağlamını oluşturur; Challenge, Rate Limit, Bot ve WAF modülleri sırayla değerlendirme yapar. Sonuç block, challenge veya allow olabilir.</p></div>
<div class="celebi-panel"><h2>Profesyonel Geliştirmeler</h2><ul><li>Dinamik DB tabanlı kural motoru</li><li>Async log kuyruğu ve cron flush</li><li>Sampling ile performans kontrolü</li><li>Gerçek IP geo lookup + cache</li><li>Davranışsal bot analizi</li><li>IP challenge/block/allow yönetimi</li><li>Gelişmiş dashboard: top IP, top URL, saldırı yoğunluğu, harita</li><li>Admin nonce ve capability kontrolleri</li></ul></div>
<div class="celebi-panel"><h2>Öneriler</h2><p>Canlı kullanımdan önce test ortamında deneyin. Kendi IP adresinizi allow listesine ekleyin. Rate limit değerini sitenizin normal trafiğine göre ayarlayın. Büyük ölçekli DDoS için sunucu veya edge/CDN seviyesi koruma önerilir.</p></div>
</div>
<?php }


function celebi_waf_render_enterprise() { ?>
<div class="wrap celebi-waf-wrap"><?php celebi_waf_header('CELEBI WAF v4 Enterprise Modüller', 'SaaS merkezi panel, Threat Intelligence, Nginx Edge-Level, IP reputation engine ve gelişmiş Bot AI yönetimi.'); ?>
<div class="celebi-module-grid">
<div class="module-card"><h3>Merkezi Yönetim Paneli</h3><strong><?php echo get_option('celebi_waf_saas_enabled','0')==='1'?'Aktif':'Pasif'; ?></strong><span>SaaS API bağlantısı</span></div>
<div class="module-card"><h3>Threat Intelligence</h3><strong><?php echo get_option('celebi_waf_threat_intel_enabled','1')==='1'?'Aktif':'Pasif'; ?></strong><span>IP reputation</span></div>
<div class="module-card"><h3>Nginx Edge-Level</h3><strong><?php echo get_option('celebi_waf_edge_enabled','1')==='1'?'Aktif':'Pasif'; ?></strong><span>Kural çıktısı</span></div>
<div class="module-card"><h3>Gelişmiş Bot AI</h3><strong><?php echo esc_html(get_option('celebi_waf_bot_ai_threshold',75)); ?></strong><span>Risk eşiği</span></div>
</div>
<div class="celebi-panel"><h2>Enterprise Ayarları</h2><table class="form-table">
<tr><th>SaaS Modülü</th><td><label><input type="checkbox" id="ent-saas-enabled" <?php checked(get_option('celebi_waf_saas_enabled','0'),'1'); ?>> Aktif</label></td></tr>
<tr><th>API Server URL</th><td><input id="ent-saas-url" class="regular-text" value="<?php echo esc_attr(get_option('celebi_waf_saas_api_url','')); ?>" placeholder="https://api.domain.com"></td></tr>
<tr><th>API Key</th><td><input id="ent-saas-key" class="regular-text" type="password" value="<?php echo esc_attr(get_option('celebi_waf_saas_api_key','')); ?>"></td></tr>
<tr><th>Site ID</th><td><input id="ent-saas-site" class="regular-text" value="<?php echo esc_attr(get_option('celebi_waf_saas_site_id','')); ?>"></td></tr>
<tr><th>Threat Intelligence</th><td><label><input type="checkbox" id="ent-threat-enabled" <?php checked(get_option('celebi_waf_threat_intel_enabled','1'),'1'); ?>> Aktif</label></td></tr>
<tr><th>Threat Feed URL</th><td><input id="ent-threat-feed" class="regular-text" value="<?php echo esc_attr(get_option('celebi_waf_threat_feed_url','')); ?>" placeholder="https://example.com/bad-ips.txt"></td></tr>
<tr><th>Nginx Edge-Level</th><td><label><input type="checkbox" id="ent-edge-enabled" <?php checked(get_option('celebi_waf_edge_enabled','1'),'1'); ?>> Aktif</label></td></tr>
<tr><th>Bot AI</th><td><label><input type="checkbox" id="ent-botai-enabled" <?php checked(get_option('celebi_waf_bot_ai_enabled','1'),'1'); ?>> Aktif</label></td></tr>
<tr><th>Bot AI Eşiği</th><td><input type="number" id="ent-botai-threshold" value="<?php echo esc_attr(get_option('celebi_waf_bot_ai_threshold',75)); ?>" min="30" max="100"></td></tr>
</table><button class="button button-primary" id="save-enterprise">Enterprise Ayarlarını Kaydet</button><button class="button" id="test-saas">SaaS Bağlantısını Test Et</button><div class="celebi-result" id="enterprise-result"></div></div>
</div>
<?php }

function celebi_waf_render_saas() { ?>
<div class="wrap celebi-waf-wrap"><?php celebi_waf_header('Merkezi Yönetim Paneli (SaaS)', 'Birden fazla WordPress sitesini merkezi API server üzerinden takip etmek için bağlantı ayarları ve örnek API server kodu.'); ?>
<div class="celebi-panel"><h2>API Server Örnek Kodu</h2><p>Bu kod ayrı bir API sunucusunda çalıştırılmak üzere örnek olarak verilmiştir.</p><textarea class="large-text code" rows="24" readonly><?php echo esc_textarea(CELEBI_WAF_Module_SaaS::api_server_template()); ?></textarea></div>
</div>
<?php }

function celebi_waf_render_threat_intel() { $rep_rows = celebi_waf_threat_reputation_snapshot(); $top_rep = $rep_rows[0] ?? ['ip'=>'-', 'feed'=>'-', 'reputation'=>0, 'action'=>'monitor']; ?>
<div class="wrap celebi-waf-wrap"><?php celebi_waf_header('Threat Intelligence ve IP Reputation', 'Düzenlenebilir feed, eşik, prefix, cache ve aksiyon politikaları ile gelişmiş IP reputation merkezi.'); ?>
<div class="threat-hero">
  <div class="threat-score"><span>Block Eşiği</span><strong><?php echo esc_html(get_option('celebi_waf_threat_block_threshold',90)); ?></strong><em>Yüksek riskli IP karar noktası</em></div>
  <div class="threat-flow"><div class="threat-ip-card"><span>IP</span><strong id="threat-hero-ip"><?php echo esc_html($top_rep['ip']); ?></strong></div><div class="threat-feed-card"><span>Feed</span><strong id="threat-hero-feed"><?php echo esc_html($top_rep['feed']); ?></strong></div><div class="threat-reputation-card"><span>Reputation</span><strong id="threat-hero-reputation"><?php echo esc_html($top_rep['reputation']); ?></strong></div><div class="threat-action-card"><span>Aksiyon</span><strong id="threat-hero-action"><?php echo esc_html($top_rep['action']); ?></strong></div></div>
</div>
<div class="celebi-grid threat-grid">
  <div class="celebi-panel"><h2>Threat Intelligence Ayarları</h2><table class="form-table">
    <tr><th>Modül Durumu</th><td><label><input type="checkbox" id="threat-enabled" <?php checked(get_option('celebi_waf_threat_intel_enabled','1'),'1'); ?>> Aktif</label></td></tr>
    <tr><th>Threat Feed URL</th><td><input id="threat-feed-url" class="regular-text" value="<?php echo esc_attr(get_option('celebi_waf_threat_feed_url','')); ?>" placeholder="https://example.com/bad-ips.txt"><p class="description">Satır bazlı IP listesi veya IP içeren metin feed desteklenir. Özel ağlara giden URL'ler güvenlik için reddedilir.</p></td></tr>
    <tr><th>Challenge Eşiği</th><td><input type="number" id="threat-challenge-threshold" value="<?php echo esc_attr(get_option('celebi_waf_threat_challenge_threshold',70)); ?>" min="10" max="100"></td></tr>
    <tr><th>Block Eşiği</th><td><input type="number" id="threat-block-threshold" value="<?php echo esc_attr(get_option('celebi_waf_threat_block_threshold',90)); ?>" min="10" max="100"></td></tr>
    <tr><th>Cache TTL</th><td><input type="number" id="threat-cache-ttl" value="<?php echo esc_attr(get_option('celebi_waf_threat_cache_ttl',360)); ?>" min="5" max="1440"> dakika</td></tr>
    <tr><th>Riskli Prefix Listesi</th><td><textarea id="threat-prefixes" class="large-text code" rows="5"><?php echo esc_textarea(get_option('celebi_waf_threat_bad_prefixes', "45.
185.
193.
198.
89.248.")); ?></textarea></td></tr>
  </table><button class="button button-primary" id="save-threat-intel">Threat Intelligence Ayarlarını Kaydet</button><button class="button" id="test-threat-intel">Mevcut IP Riskini Test Et</button><div class="celebi-result" id="threat-intel-result"></div></div>
  <div class="celebi-panel"><h2>Operasyon Paneli</h2><ul class="feature-list"><li>Feed URL doğrulama ve SSRF riskini azaltan güvenli URL kontrolü</li><li>IP reputation cache ile düşük gecikmeli karar üretimi</li><li>Challenge ve block eşiklerinin panelden düzenlenebilmesi</li><li>Riskli IP prefix listesini ortamınıza göre özelleştirme</li><li>Bot AI, WAF Motoru ve IP Challenge ile korelasyonlu çalışma</li></ul></div>
</div>
<div class="celebi-panel threat-reputation-panel">
  <h2>Threat Intelligence ve IP Reputation</h2>
  <p class="description">Bu liste manuel reputation kayıtları, son WAF logları, feed eşleşmeleri ve mevcut IP testinden beslenir. IP, Feed, Reputation ve Aksiyon alanları boş kalmaması için sistem varsayılan örnek kayıt ve log korelasyonu üretir.</p>
  <div class="reputation-form">
    <input type="text" id="rep-ip" placeholder="IP adresi örn: 203.0.113.10">
    <input type="text" id="rep-feed" placeholder="Feed kaynağı örn: Manual SOC">
    <input type="number" id="rep-score" min="0" max="100" value="75" placeholder="Reputation">
    <select id="rep-action"><option value="monitor">İzle</option><option value="challenge">Challenge</option><option value="block">Block</option><option value="allow">Allow</option></select>
    <input type="text" id="rep-note" placeholder="Not / açıklama">
    <button class="button button-primary" id="save-threat-reputation">Kaydı Ekle / Güncelle</button>
  </div>
  <div class="celebi-result" id="threat-reputation-result"></div>
  <div class="table-scroll"><table class="widefat striped"><thead><tr><th>IP</th><th>Feed</th><th>Reputation</th><th>Aksiyon</th><th>Kaynak</th><th>Son Güncelleme</th><th>İşlem</th></tr></thead><tbody id="threat-reputation-table"><?php celebi_waf_render_threat_reputation_rows(); ?></tbody></table></div>
</div>
<div class="celebi-module-grid threat-cards"><div class="module-card sql-xss"><h3>Feed Eşleşmesi</h3><strong>95+</strong><ul><li>Harici kötü IP listeleri</li><li>Cache destekli sorgu</li><li>Otomatik block önerisi</li></ul></div><div class="module-card ip-challenge"><h3>Orta Risk</h3><strong>70+</strong><ul><li>Challenge aksiyonu</li><li>Davranışsal gözlem</li><li>Log korelasyonu</li></ul></div><div class="module-card async-log"><h3>Yerel Heuristics</h3><strong>Prefix</strong><ul><li>Düzenlenebilir IP prefixleri</li><li>Risk puanı toplama</li><li>Private IP filtreleme</li></ul></div></div>
</div>
<?php }

function celebi_waf_render_edge() { ?>
<div class="wrap celebi-waf-wrap"><?php celebi_waf_header('Nginx Edge-Level Koruma', 'WordPress öncesinde çalışacak Nginx kural çıktısı. Bu kuralı sunucu yöneticiniz kontrollü uygulamalıdır.'); ?>
<div class="celebi-panel"><h2>Nginx Kural Çıktısı</h2><button class="button button-primary" id="load-edge-rules">Kuralı Oluştur</button><div class="celebi-result" id="edge-result"></div><textarea class="large-text code" rows="22" id="edge-rules-output" readonly></textarea></div>
</div>
<?php }

function celebi_waf_render_bot_ai() { $bot = celebi_waf_bot_ai_snapshot(); ?>
<div class="wrap celebi-waf-wrap"><?php celebi_waf_header('Gelişmiş Bot AI', 'Davranışsal bot skorlama, headless izleri, hassas endpoint ve tekrar paterni analizi.'); ?>
<div class="bot-ai-hero">
  <div class="bot-ai-score"><span>Risk Eşiği</span><strong id="bot-ai-threshold-live"><?php echo esc_html($bot['threshold']); ?></strong><em>Challenge / block karar motoru</em></div>
  <div class="bot-ai-flow"><div class="bot-request-card"><span>İstek</span><strong id="bot-ai-requests"><?php echo esc_html($bot['requests']); ?></strong></div><div class="bot-fingerprint-card"><span>Fingerprint</span><strong id="bot-ai-fingerprint"><?php echo esc_html($bot['fingerprint']); ?></strong></div><div class="bot-score-card"><span>Skor</span><strong id="bot-ai-score"><?php echo esc_html($bot['score']); ?></strong></div><div class="bot-action-card"><span>Aksiyon</span><strong id="bot-ai-action"><?php echo esc_html($bot['action']); ?></strong></div></div>
</div>
<div class="celebi-grid bot-ai-grid">
  <div class="celebi-panel"><h2>Algılama Katmanları</h2><ul class="feature-list"><li>Headless browser, webdriver ve otomasyon izleri</li><li>Boş/şüpheli User-Agent, aşırı kısa oturum ve anormal header yapısı</li><li>wp-login, xmlrpc.php, wp-json ve admin-ajax gibi hassas endpoint davranışı</li><li>Aynı URL tekrar paterni, dakikalık IP frekansı ve burst analizi</li><li>Threat Intelligence ile IP reputation sinyali</li></ul></div>
  <div class="celebi-panel"><h2>Bot AI Ayarları</h2><table class="form-table">
    <tr><th>Bot AI</th><td><label><input type="checkbox" id="botai-enabled" <?php checked(get_option('celebi_waf_bot_ai_enabled','1'),'1'); ?>> Aktif</label></td></tr>
    <tr><th>Risk Eşiği</th><td><input type="number" id="botai-threshold" value="<?php echo esc_attr(get_option('celebi_waf_bot_ai_threshold',75)); ?>" min="30" max="100"> <span class="description">30-100 arası.</span></td></tr>
    <tr><th>Hassas Endpointler</th><td><textarea id="botai-endpoints" class="large-text code" rows="4"><?php echo esc_textarea(get_option('celebi_waf_bot_ai_endpoints', 'wp-login.php
xmlrpc.php
wp-json
admin-ajax.php')); ?></textarea></td></tr>
    <tr><th>Şüpheli UA İmzaları</th><td><textarea id="botai-signatures" class="large-text code" rows="4"><?php echo esc_textarea(get_option('celebi_waf_bot_ai_signatures', 'headless
python-requests
curl
selenium
phantomjs')); ?></textarea></td></tr>
  </table><button class="button button-primary" id="save-bot-ai">Bot AI Ayarlarını Kaydet</button><div class="celebi-result" id="bot-ai-result"></div></div>
</div>
<div class="celebi-module-grid bot-ai-cards"><div class="module-card traffic-monitor"><h3>Davranış Analizi</h3><strong>Gerçek Zamanlı</strong><ul><li>Frekans</li><li>Tekrar paterni</li><li>Oturum süresi</li></ul></div><div class="module-card bot-block"><h3>Fingerprint</h3><strong>Header + UA</strong><ul><li>Webdriver</li><li>Headless</li><li>Anormal header</li></ul></div><div class="module-card ip-challenge"><h3>Aksiyon Motoru</h3><strong>Allow / Challenge / Block</strong><ul><li>Eşik bazlı karar</li><li>IP challenge</li><li>Log korelasyonu</li></ul></div></div>
</div>
<?php }
