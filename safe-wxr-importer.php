<?php
/**
 * Plugin Name: Safe WXR Importer
 * Description: Import WordPress WXR exports with quarantined, validated image downloads and conservative cybersecurity defaults, does not guarantee safety.
 * Version: 0.0.3
 * Requires at least: 6.2
 * Requires PHP: 7.4
 * Author: Lucas
 * Text Domain: safe-wxr-importer
 */

if (!defined('ABSPATH')) {
    exit;
}

class Safe_WXR_Importer {
    const V = '0.0.3';
    const MX = 15728640;       // WXR maximum: 15 MiB
    const MI = 12582912;       // Image maximum: 12 MiB
    const MI2 = 250;           // Maximum image attachments processed per import
    const MR = 3;              // Maximum redirects
    const AM = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp'];

    public static function init() {
        add_action('admin_menu', [__CLASS__, 'register_menu']);
        add_action('admin_post_swi_import', [__CLASS__, 'handle_import']);
    }

    public static function register_menu() {
        add_management_page('Safe WXR Importer', 'Safe WXR Importer', 'import', 'safe-wxr-importer', [__CLASS__, 'page']);
    }

    public static function page() {
        if (!current_user_can('import')) {
            wp_die(esc_html__('You do not have permission to import content.', 'safe-wxr-importer'));
        }
        ?>
        <div class="wrap">
            <h1>Safe WXR Importer</h1>
            <p>Import posts, pages, categories, tags, and optionally approved images from a WXR export.</p>
            <div class="notice notice-warning"><p><strong>Security note:</strong> Use a staging site and backup first. Only JPEG, PNG, and WebP images are imported.</p></div>
            <?php if (!empty($_GET['swi_result'])) : ?>
                <div class="notice notice-info"><p><?php echo esc_html(wp_unslash($_GET['swi_result'])); ?></p></div>
            <?php endif; ?>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" enctype="multipart/form-data">
                <input type="hidden" name="action" value="swi_import">
                <?php wp_nonce_field('swi_import', 'swi_nonce'); ?>
                <table class="form-table">
                    <tr><th><label for="swi_wxr">WXR XML file</label></th><td><input type="file" id="swi_wxr" name="swi_wxr" accept=".xml,text/xml,application/xml" required><p class="description">Max 15 MB.</p></td></tr>
                    <tr><th>Media</th><td><label><input type="checkbox" name="swi_import_media" value="1"> Download images (opt-in, public HTTP(S) only, JPEG/PNG/WebP â‰¤12 MB)</label></td></tr>
                    <tr><th>Existing</th><td><label><input type="checkbox" name="swi_skip_existing" value="1" checked> Skip existing posts/pages by slug</label></td></tr>
                </table>
                <?php submit_button('Import safely'); ?>
            </form>
        </div>
        <?php
    }

    public static function handle_import() {
        if (!current_user_can('import')) {
            wp_die(esc_html__('No permission.', 'safe-wxr-importer'));
        }
        check_admin_referer('swi_import', 'swi_nonce');

        $f = $_FILES['swi_wxr'] ?? [];
        if (empty($f) || !isset($f['error']) || UPLOAD_ERR_OK !== (int) $f['error']) {
            self::redirect('Upload failed.');
        }
        if (!empty($f['size']) && (int) $f['size'] > self::MX) {
            self::redirect('File exceeds 15 MB.');
        }
        $tmp = $f['tmp_name'] ?? '';
        if (!$tmp || !is_uploaded_file($tmp)) {
            self::redirect('Invalid upload.');
        }
        $raw = file_get_contents($tmp);
        if ($raw === false || $raw === '' || strlen($raw) > self::MX) {
            self::redirect('Could not read file.');
        }
        if (preg_match('/<!DOCTYPE\b/i', $raw)) {
            self::redirect('DOCTYPE not allowed.');
        }

        libxml_use_internal_errors(true);
        $xml = simplexml_load_string($raw, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOCDATA | LIBXML_COMPACT);
        if (!$xml || strtolower($xml->getName()) !== 'rss') {
            libxml_clear_errors();
            self::redirect('Not a valid WXR file.');
        }
        $ns = $xml->getNamespaces(true);
        if (empty($ns['wp'])) {
            self::redirect('No WordPress WXR data found.');
        }

        $wpns = $ns['wp'];
        $ch = $xml->channel;
        $items = $ch->item ?? [];
        $im = !empty($_POST['swi_import_media']);
        $sk = !empty($_POST['swi_skip_existing']);
        $uid = get_current_user_id();
        $um = [];                 // Original URL => local URL
        $am = [];                 // Source attachment ID => local attachment ID
        $pi = [];                 // Local post ID => source featured attachment ID
        $c = ['cr' => 0, 'sk' => 0, 'md' => 0, 'mf' => 0, 'er' => 0, 'media_limit' => 0];
        $fc = ['pending' => 0, 'assigned' => 0, 'failed' => 0, 'missing' => 0];
        $ms = 0;
        $tm = self::it($ch, $wpns);

        foreach ($items as $item) {
            $iw = $item->children($wpns);
            $tid = 0;
            foreach ($iw->postmeta as $m) {
                if ((string) $m->meta_key === '_thumbnail_id') {
                    $tid = (int) $m->meta_value;
                    break;
                }
            }

            $t = (string) $iw->post_type;
            $s = (string) $iw->status;
            $sl = sanitize_title((string) $iw->post_name);

            if ($t === 'attachment') {
                $u = trim((string) $iw->attachment_url);
                $aid = (int) $iw->post_id;
                if ($im && $u !== '' && $ms < self::MI2) {
                    $ms++;
                    $r = self::ii($u, (string) $item->title, $uid);
                    if (is_wp_error($r)) {
                        $c['mf']++;
                        error_log(sprintf('[SWI] Image import failed: source_url=%s code=%s message=%s', $u, $r->get_error_code(), $r->get_error_message()));
                    } else {
                        $c['md']++;
                        if ($aid > 0) {
                            $am[$aid] = (int) $r;
                        }
                        $lu = wp_get_attachment_url($r);
                        if ($lu) {
                            $um[$u] = $lu;
                        }
                    }
                } elseif ($im && $u !== '' && $ms >= self::MI2) {
                    $c['media_limit']++;
                    error_log(sprintf('[SWI] Media limit reached: source_attachment=%d source_url=%s', $aid, $u));
                }
                continue;
            }

            if (!in_array($t, ['post', 'page'], true)) {
                continue;
            }
            if (!in_array($s, ['publish', 'future', 'draft', 'pending', 'private'], true)) {
                $s = 'draft';
            }
            $ti = wp_strip_all_tags((string) $item->title, true);
            $co = (string) $item->children('content', true)->encoded;
            if ($co === '') {
                $co = (string) $item->description;
            }
            $co = wp_kses_post($co);
            $g = (string) $item->guid;

            if ($sk && $sl !== '' && get_page_by_path($sl, OBJECT, $t)) {
                $c['sk']++;
                continue;
            }

            $pa = [
                'post_type' => $t,
                'post_status' => $s,
                'post_title' => $ti,
                'post_name' => $sl,
                'post_content' => $co,
                'post_excerpt' => wp_kses_post((string) $item->description),
                'post_date' => self::sd((string) $item->pubDate),
                'post_author' => $uid,
                'comment_status' => 'closed',
                'ping_status' => 'closed',
            ];
            $pid = wp_insert_post(wp_slash($pa), true);
            if (is_wp_error($pid)) {
                $c['er']++;
                error_log(sprintf('[SWI] Post creation failed: type=%s slug=%s message=%s', $t, $sl, $pid->get_error_message()));
                continue;
            }
            $c['cr']++;
            if ($sl !== '') {
                update_post_meta($pid, '_swi_source_slug', $sl);
            }
            if ($g !== '') {
                update_post_meta($pid, '_swi_source_guid_hash', hash('sha256', $g));
            }
            self::at($item, $wpns, $pid, $tm);
            if ($tid > 0) {
                $pi[$pid] = $tid;
            }
        }

        // Assign featured images only after all attachment items have been processed
        if ($im && !empty($pi)) {
            foreach ($pi as $pid => $sid) {
                $pid = (int) $pid;
                $sid = (int) $sid;
                $fc['pending']++;

                if (!isset($am[$sid])) {
                    $fc['missing']++;
                    error_log(sprintf('[SWI] Featured image missing: post=%d source_attachment=%d', $pid, $sid));
                    continue;
                }

                $na = (int) $am[$sid];
                if ($na <= 0 || get_post_type($na) !== 'attachment' || !wp_attachment_is_image($na)) {
                    $fc['failed']++;
                    error_log(sprintf('[SWI] Invalid image attachment: post=%d source_attachment=%d local_attachment=%d', $pid, $sid, $na));
                    continue;
                }

                $result = set_post_thumbnail($pid, $na);
                if ((int) get_post_thumbnail_id($pid) === $na) {
                    $fc['assigned']++;
                } else {
                    $fc['failed']++;
                    error_log(sprintf('[SWI] Featured image assignment failed: post=%d source_attachment=%d local_attachment=%d result=%s', $pid, $sid, $na, var_export($result, true)));
                }
            }
        }

        // Replace imported image URLs in content. Featured images are handled separately above
        if (!empty($um)) {
            foreach (get_posts([
                'post_type' => ['post', 'page'],
                'post_status' => ['publish', 'future', 'draft', 'pending', 'private'],
                'numberposts' => -1,
                'meta_key' => '_swi_source_guid_hash',
            ]) as $p) {
                $content = str_replace(array_keys($um), array_values($um), $p->post_content);
                if ($content !== $p->post_content) {
                    wp_update_post(['ID' => $p->ID, 'post_content' => $content]);
                }
            }
        }

        self::redirect(sprintf(
            'Done. Created:%d Skipped:%d Images imported:%d Image failures:%d Post errors:%d Featured pending:%d Featured assigned:%d Featured failed:%d Featured missing attachment:%d Media limit skipped:%d',
            $c['cr'], $c['sk'], $c['md'], $c['mf'], $c['er'],
            $fc['pending'], $fc['assigned'], $fc['failed'], $fc['missing'], $c['media_limit']
        ));
    }

    private static function it($ch, $wpns) {
        $map = ['category' => [], 'tag' => []];
        foreach (['category' => 'category', 'tag' => 'tag'] as $k => $tax) {
            foreach ($ch->children($wpns)->{$k} as $term) {
                $tw = $term->children($wpns);
                $n = sanitize_text_field((string) $term->name);
                $s = sanitize_title((string) $term->slug);
                if ($n === '') {
                    continue;
                }
                $e = term_exists($s !== '' ? $s : $n, $tax);
                if (!$e) {
                    $e = wp_insert_term($n, $tax, ['slug' => $s]);
                }
                if (!is_wp_error($e)) {
                    $map[$k][(string) $tw->term_id] = (int) (is_array($e) ? $e['term_id'] : $e);
                }
            }
        }
        return $map;
    }

    private static function at($item, $wpns, $pid, $tm) {
        $tax = ['category' => [], 'tag' => []];
        foreach ($item->category as $cat) {
            $d = (string) $cat['domain'];
            $n = (string) $cat['nicename'];
            if ($d === 'category' && isset($tm['category'])) {
                foreach ($tm['category'] as $m) {
                    $t = get_term($m, 'category');
                    if ($t && ($t->slug === $n || $t->name === (string) $cat)) {
                        $tax['category'][] = $m;
                    }
                }
            } elseif ($d === 'post_tag') {
                $t = get_term_by('slug', sanitize_title($n), 'post_tag');
                if ($t) {
                    $tax['tag'][] = (int) $t->term_id;
                }
            }
        }
        if ($tax['category']) {
            wp_set_post_terms($pid, array_values(array_unique($tax['category'])), 'category');
        }
        if ($tax['tag']) {
            wp_set_post_terms($pid, array_values(array_unique($tax['tag'])), 'post_tag');
        }
    }

    private static function ii($url, $title, $uid) {
        // Deliberately do not reuse attachments by filename: identical filenames can contain different images
        $source_path = wp_parse_url($url, PHP_URL_PATH);
        $source_filename = sanitize_file_name(rawurldecode(wp_basename((string) $source_path)));
        $download = self::sdi($url);
        if (is_wp_error($download)) {
            return $download;
        }

        $path = $download['path'];
        $mime = $download['mime'];
        $editor = wp_get_image_editor($path);
        if (is_wp_error($editor)) {
            @unlink($path);
            return new WP_Error('swi_decode', 'Image decode failed.');
        }

        $safe_path = wp_tempnam('swi.' . self::AM[$mime]);
        if (!$safe_path) {
            @unlink($path);
            return new WP_Error('swi_temp', 'Could not create temporary file.');
        }
        $saved = $editor->save($safe_path, $mime);
        @unlink($path);
        if (is_wp_error($saved) || empty($saved['path']) || !is_file($saved['path'])) {
            @unlink($safe_path);
            return new WP_Error('swi_reenc', 'Image re-encoding failed.');
        }

        $final_path = $saved['path'];
        $saved_mime = isset($saved['mime-type']) ? $saved['mime-type'] : $mime;
        if (!isset(self::AM[$saved_mime]) || !is_file($final_path) || filesize($final_path) > self::MI) {
            @unlink($final_path);
            return new WP_Error('swi_out', 'Invalid image output.');
        }

        $base = $source_filename !== '' ? pathinfo($source_filename, PATHINFO_FILENAME) : sanitize_title($title ?: 'image');
        if ($base === '') {
            $base = 'image';
        }
        $filename = sanitize_file_name($base . '.' . self::AM[$saved_mime]);
        $file_array = [
            'name' => $filename,
            'tmp_name' => $final_path,
            'type' => $saved_mime,
            'size' => filesize($final_path),
            'error' => 0,
        ];

        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/media.php';
        require_once ABSPATH . 'wp-admin/includes/image.php';
        $attachment_id = media_handle_sideload($file_array, 0, sanitize_text_field($title));
        if (is_wp_error($attachment_id)) {
            if (file_exists($final_path)) {
                @unlink($final_path);
            }
            return $attachment_id;
        }
        wp_update_post(['ID' => $attachment_id, 'post_author' => $uid]);
        update_post_meta($attachment_id, '_swi_imported_safe_image', 1);
        return (int) $attachment_id;
    }

    private static function sdi($url) {
        $url = esc_url_raw($url, ['http', 'https']);
        if (!$url || !self::ipu($url)) {
            return new WP_Error('swi_url', 'Invalid or private URL.');
        }
        $current = $url;
        for ($i = 0; $i <= self::MR; $i++) {
            if (!self::ipu($current)) {
                return new WP_Error('swi_redir', 'Invalid redirect destination.');
            }
            $response = wp_safe_remote_get($current, [
                'timeout' => 15,
                'redirection' => 0,
                'limit_response_size' => self::MI + 1,
                'headers' => ['Accept' => 'image/jpeg,image/png,image/webp'],
                'user-agent' => 'SWI/' . self::V . '; ' . home_url('/'),
                'reject_unsafe_urls' => true,
            ]);
            if (is_wp_error($response)) {
                return $response;
            }
            $code = (int) wp_remote_retrieve_response_code($response);
            if (in_array($code, [301, 302, 303, 307, 308], true)) {
                if ($i >= self::MR) {
                    return new WP_Error('swi_redir_max', 'Too many redirects.');
                }
                $location = wp_remote_retrieve_header($response, 'location');
                if (!$location) {
                    return new WP_Error('swi_redir_no', 'Redirect has no location.');
                }
                $current = WP_Http::make_absolute_url($location, $current);
                continue;
            }
            if ($code !== 200) {
                return new WP_Error('swi_http', 'HTTP ' . $code . '.');
            }
            $body = wp_remote_retrieve_body($response);
            if (!is_string($body) || $body === '' || strlen($body) > self::MI) {
                return new WP_Error('swi_size', 'Invalid or oversized image response.');
            }
            $tmp = wp_tempnam('swi-dl');
            if (!$tmp) {
                return new WP_Error('swi_temp', 'Could not create temporary file.');
            }
            if (file_put_contents($tmp, $body, LOCK_EX) === false) {
                @unlink($tmp);
                return new WP_Error('swi_write', 'Could not write temporary file.');
            }
            $detected = self::dim($tmp);
            if (!$detected) {
                @unlink($tmp);
                return new WP_Error('swi_mime', 'Response is not a supported valid image.');
            }
            return ['path' => $tmp, 'mime' => $detected];
        }
        return new WP_Error('swi_dl', 'Download failed.');
    }

    private static function dim($path) {
        if (!is_file($path) || filesize($path) < 12 || filesize($path) > self::MI) {
            return false;
        }
        $fi = function_exists('finfo_open') ? finfo_open(FILEINFO_MIME_TYPE) : false;
        $mime = $fi ? finfo_file($fi, $path) : '';
        if ($fi) {
            finfo_close($fi);
        }
        if (!isset(self::AM[$mime])) {
            return false;
        }
        $info = @getimagesize($path);
        if (!$info || empty($info['mime']) || $info['mime'] !== $mime) {
            return false;
        }
        $head = file_get_contents($path, false, null, 0, 16);
        if ($mime === 'image/jpeg' && substr((string) $head, 0, 3) !== "\xFF\xD8\xFF") {
            return false;
        }
        if ($mime === 'image/png' && substr((string) $head, 0, 8) !== "\x89PNG\r\n\x1A\n") {
            return false;
        }
        if ($mime === 'image/webp' && (substr((string) $head, 0, 4) !== 'RIFF' || substr((string) $head, 8, 4) !== 'WEBP')) {
            return false;
        }
        return $mime;
    }

    private static function ipu($url) {
        $parts = wp_parse_url($url);
        if (!$parts || empty($parts['scheme']) || empty($parts['host']) || !in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
            return false;
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }
        $host = strtolower(rtrim($parts['host'], '.'));
        if ($host === 'localhost' || substr($host, -10) === '.localhost' || substr($host, -6) === '.local' || substr($host, -4) === '.lan' || substr($host, -9) === '.internal') {
            return false;
        }
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return (bool) filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
        }

        $ips = [];
        if (function_exists('dns_get_record')) {
            $records = @dns_get_record($host, DNS_A + DNS_AAAA);
            if (is_array($records)) {
                foreach ($records as $record) {
                    if (!empty($record['ip'])) {
                        $ips[] = $record['ip'];
                    }
                    if (!empty($record['ipv6'])) {
                        $ips[] = $record['ipv6'];
                    }
                }
            }
        }
        if (!$ips) {
            $resolved = @gethostbynamel($host);
            if (is_array($resolved)) {
                $ips = $resolved;
            }
        }
        if (!$ips) {
            return false;
        }
        foreach (array_unique($ips) as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return false;
            }
        }
        return true;
    }

    private static function sd($date) {
        if (!$date) {
            return current_time('mysql');
        }
        $timestamp = strtotime($date);
        if (!$timestamp || $timestamp < 0) {
            return current_time('mysql');
        }
        return gmdate('Y-m-d H:i:s', $timestamp);
    }

    private static function redirect($message) {
        wp_safe_redirect(add_query_arg(['page' => 'safe-wxr-importer', 'swi_result' => $message], admin_url('tools.php')));
        exit;
    }
}

Safe_WXR_Importer::init();