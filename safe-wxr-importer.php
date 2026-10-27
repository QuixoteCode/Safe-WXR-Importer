<?php
/**
* Plugin Name: Safe WXR Importer
* Description: Import WordPress WXR exports with quarantined, validated image downloads and conservative cybersecurity defaults, does not guarantee safety.
* Version: 0.0.1
* Requires at least: 6.2
* Requires PHP: 7.4
* Author: Lucas
* Text Domain: safe-wxr-importer
*/

if (!defined('ABSPATH')) {
    exit;
}

class Safe_WXR_Importer {
    const VERSION = '0.0.1';
    const MAX_XML_BYTES = 15 * 1024 * 1024;
    const MAX_IMAGE_BYTES = 12 * 1024 * 1024;
    const MAX_IMAGES = 250;
    const MAX_REDIRECTS = 3;
    const ALLOWED_MIMES = array(
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/webp' => 'webp',
    );

    public static function init() {
        add_action('admin_menu', array(__CLASS__, 'register_menu'));
        add_action('admin_post_swi_import', array(__CLASS__, 'handle_import'));
    }

    public static function register_menu() {
        add_management_page(
            'Safe WXR Importer',
            'Safe WXR Importer',
            'import',
            'safe-wxr-importer',
            array(__CLASS__, 'page')
        );
    }

    public static function page() {
        if (!current_user_can('import')) {
            wp_die(esc_html__('You do not have permission to import content.', 'safe-wxr-importer'));
        }
    ?>

    <div class="wrap">
        <h1>Safe WXR Importer</h1>
        <p>Import posts, pages, categories, tags, and optionally approved images from a WordPress eXtended RSS (WXR) export.</p>
        <div class="notice notice-warning"><p><strong>Security note:</strong> Use a staging site and backup first. This importer reduces risk but cannot guarantee files are harmless. It imports only JPEG, PNG, and WebP images; SVG, PDF, HTML, and executable files are excluded.</p></div>

        <?php if (!empty($_GET['swi_result'])): ?>

            <div class="notice notice-info"><p><?php echo esc_html(wp_unslash($_GET['swi_result'])); ?></p></div>

        <?php endif; ?>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" enctype="multipart/form-data">
            <input type="hidden" name="action" value="swi_import">

            <?php wp_nonce_field('swi_import', 'swi_nonce'); ?>

            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row">
                        <label for="swi_wxr">WXR XML file</label>
                    </th>
                    <td>
                        <input
                            type="file"
                            id="swi_wxr"
                            name="swi_wxr"
                            accept=".xml,text/xml,application/xml"
                            required
                        >
                        <p class="description">
                            Maximum file size: 15 MB. Upload a WordPress export XML file.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Media handling</th>
                    <td>
                        <label>
                            <input
                                type="checkbox"
                                name="swi_import_media"
                                value="1"
                            >
                            Download and import eligible images referenced by attachment records
                        </label>
                        <p class="description">
                            Off by default. Only public HTTP(S) URLs and JPEG, PNG, or WebP images
                            up to 12 MB are accepted. Downloads are not followed automatically
                            through redirects; each redirect is revalidated.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Existing content</th>
                    <td>
                        <label>
                            <input
                                type="checkbox"
                                name="swi_skip_existing"
                                value="1"
                                checked
                            >
                            Skip posts/pages with the same post type and slug
                        </label>
                    </td>
                </tr>
            </table>
            <?php submit_button('Import safely'); ?>
        </form>
        <hr><h2>Included safeguards</h2>
        <ul style="list-style:disc;padding-left:24px;">
            <li>Requires WordPress import capability and a valid nonce.</li>
            <li>Rejects oversized XML and documents containing a DOCTYPE declaration.</li>
            <li>Parses XML without network access or entity substitution.</li>
            <li>Does not execute imported content, PHP, or scripts.</li>
            <li>Media fetching is opt-in, size-limited, redirect-limited, and blocks local/private IP destinations.</li>
            <li>Checks file signatures and MIME types; rejects SVG and non-raster files.</li>
            <li>Re-encodes accepted images with the WordPress image editor before adding them to the Media Library.</li>
        </ul>
    </div>
    <?php
}

public static function handle_import() {
    if (!current_user_can('import')) {
        wp_die(esc_html__('You do not have permission to import content.', 'safe-wxr-importer'));
    }
    check_admin_referer('swi_import', 'swi_nonce');

    if (empty($_FILES['swi_wxr']) || !isset($_FILES['swi_wxr']['error']) || UPLOAD_ERR_OK !== (int) $_FILES['swi_wxr']['error']) {
        self::redirect('Upload failed. Please select a valid XML file.');
    }

    $file = $_FILES['swi_wxr'];

    if (!empty($file['size']) && (int) $file['size'] > self::MAX_XML_BYTES) {
        self::redirect('XML file exceeds the 15 MB limit.');
    }

    $tmp = isset($file['tmp_name']) ? $file['tmp_name'] : '';

    if (!$tmp || !is_uploaded_file($tmp)) {
        self::redirect('The uploaded file could not be verified.');
    }

    $raw = file_get_contents($tmp);

    if ($raw === false || $raw === '' || strlen($raw) > self::MAX_XML_BYTES) {
        self::redirect('Could not read the XML file or file is too large.');
    }

    if (preg_match('/<!DOCTYPE\b/i', $raw)) {
        self::redirect('XML with a DOCTYPE declaration is not accepted.');
    }

    libxml_use_internal_errors(true);
    $xml = simplexml_load_string($raw, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOCDATA | LIBXML_COMPACT);

    if (!$xml || strtolower($xml->getName()) !== 'rss') {
        libxml_clear_errors();
        self::redirect('The file is not a valid WordPress WXR RSS export.');
    }

    $namespaces = $xml->getNamespaces(true);

    if (empty($namespaces['wp'])) {
        self::redirect('This XML does not appear to contain WordPress WXR data.');
    }

    $wpns = $namespaces['wp'];
    $channel = $xml->channel;
    $items = isset($channel->item) ? $channel->item : array();
    $import_media = !empty($_POST['swi_import_media']);
    $skip_existing = !empty($_POST['swi_skip_existing']);
    $author_id = get_current_user_id();
    $url_map = array();
    $counts = array('created' => 0, 'skipped' => 0, 'media' => 0, 'media_failed' => 0, 'errors' => 0);
    $media_seen = 0;

    // Create terms before posts so categories and tags can be assigned
    $term_map = self::import_terms($channel, $wpns);

    foreach ($items as $item) {
        $item_wp = $item->children($wpns);
        $type = (string) $item_wp->post_type;
        $status = (string) $item_wp->status;
        $slug = sanitize_title((string) $item_wp->post_name);

        if ($type === 'attachment') {
            $source_url = trim((string) $item_wp->attachment_url);

            if ($import_media && $source_url !== '' && $media_seen < self::MAX_IMAGES) {
                $media_seen++;
                $attachment_id = self::import_image($source_url, (string) $item->title, $author_id);

                if (is_wp_error($attachment_id)) {
                    $counts['media_failed']++;
                } else {
                    $counts['media']++;
                    $url_map[$source_url] = wp_get_attachment_url($attachment_id);
                }
            }

            continue;
        }

        if (!in_array($type, array('post', 'page'), true)) {
            continue;
        }

        if (!in_array($status, array('publish', 'future', 'draft', 'pending', 'private'), true)) {
            $status = 'draft';
        }

        $title = wp_strip_all_tags((string) $item->title, true);
        $content = (string) $item->children('content', true)->encoded;

        if ($content === '') {
            $content = (string) $item->description;
        }

        $content = wp_kses_post($content);
        $guid = (string) $item->guid;

        if ($skip_existing && $slug !== '') {
            $existing = get_page_by_path($slug, OBJECT, $type);

            if ($existing) {
                $counts['skipped']++;
                continue;
            }
        }

        $postarr = array(
            'post_type' => $type,
            'post_status' => $status,
            'post_title' => $title,
            'post_name' => $slug,
            'post_content' => $content,
            'post_excerpt' => wp_kses_post((string) $item->description),
            'post_date' => self::safe_date((string) $item->pubDate),
            'post_author' => $author_id,
            'comment_status' => 'closed',
            'ping_status' => 'closed',
        );

        $post_id = wp_insert_post(wp_slash($postarr), true);

        if (is_wp_error($post_id)) {
            $counts['errors']++;
            continue;
        }

        $counts['created']++;

        if ($slug !== '') {
            update_post_meta($post_id, '_swi_source_slug', $slug);
        }

        if ($guid !== '') {
            update_post_meta($post_id, '_swi_source_guid_hash', hash('sha256', $guid));
        }

        self::assign_item_terms($item, $wpns, $post_id, $term_map);
    }

    // Replace source attachment URLs only when a corresponding safe local image was imported
    if (!empty($url_map)) {
        foreach (get_posts(array('post_type' => array('post','page'), 'post_status' => array('publish','future','draft','pending','private'), 'numberposts' => -1, 'meta_key' => '_swi_source_guid_hash')) as $post) {
            $content = $post->post_content;
            $updated = str_replace(array_keys($url_map), array_values($url_map), $content);

            if ($updated !== $content) {
                wp_update_post(array('ID' => $post->ID, 'post_content' => $updated));
            }
        }
    }

    $message = sprintf('Import complete. Created: %d; skipped: %d; images imported: %d; image failures: %d; content errors: %d.', $counts['created'], $counts['skipped'], $counts['media'], $counts['media_failed'], $counts['errors']);
    self::redirect($message);
}

private static function import_terms($channel, $wpns) {
    $map = array('category' => array(), 'tag' => array());

    foreach (array('category' => 'category', 'tag' => 'tag') as $kind => $taxonomy) {
        foreach ($channel->children($wpns)->{$kind} as $term) {
            $termwp = $term->children($wpns);
            $name = sanitize_text_field((string) $term->name);
            $slug = sanitize_title((string) $term->slug);

            if ($name === '') {
                continue;
            }

            $existing = term_exists($slug !== '' ? $slug : $name, $taxonomy);

            if (!$existing) {
                $existing = wp_insert_term($name, $taxonomy, array('slug' => $slug));
            }

            if (!is_wp_error($existing)) {
                $map[$kind][(string) $termwp->term_id] = (int) (is_array($existing) ? $existing['term_id'] : $existing);
            }
        }
    }

    return $map;
}

private static function assign_item_terms($item, $wpns, $post_id, $term_map) {
    $tax = array('category' => array(), 'tag' => array());

    foreach ($item->category as $cat) {
        $domain = (string) $cat['domain'];
        $nicename = (string) $cat['nicename'];

        if ($domain === 'category' && isset($term_map['category'])) {
            foreach ($term_map['category'] as $id => $mapped) {
                $term = get_term($mapped, 'category');

                if ($term && ($term->slug === $nicename || $term->name === (string) $cat)) {
                    $tax['category'][] = $mapped;
                }
            }
        } elseif ($domain === 'post_tag') {
            $term = get_term_by('slug', sanitize_title($nicename), 'post_tag');

            if ($term) {
                $tax['tag'][] = (int) $term->term_id;
            }
        }
    }

    if ($tax['category']) {
        wp_set_post_terms($post_id, array_values(array_unique($tax['category'])), 'category');
    }

    if ($tax['tag']) {
        wp_set_post_terms($post_id, array_values(array_unique($tax['tag'])), 'post_tag');
    }
}

private static function import_image($url, $title, $author_id) {
    $download = self::safe_download_image($url);

    if (is_wp_error($download)) {
        return $download;
    }

    $path = $download['path'];
    $mime = $download['mime'];
    $ext = self::ALLOWED_MIMES[$mime];
    $editor = wp_get_image_editor($path);

    if (is_wp_error($editor)) {
        @unlink($path);
        return new WP_Error('swi_image_decode', 'Image could not be decoded by the configured WordPress image editor.');
    }

    $safe_path = wp_tempnam('swi-safe-image.' . $ext);

    if (!$safe_path) {
        @unlink($path);
        return new WP_Error('swi_temp', 'Could not create a temporary image file.');
    }

    $saved = $editor->save($safe_path, $mime);
    @unlink($path);

    if (is_wp_error($saved) || empty($saved['path']) || !is_file($saved['path'])) {
        @unlink($safe_path);
        return new WP_Error('swi_reencode', 'Image could not be re-encoded safely.');
    }

    $safe_file = $saved['path'];
    $safe_mime = isset($saved['mime-type']) ? $saved['mime-type'] : $mime;

    if (!isset(self::ALLOWED_MIMES[$safe_mime]) || filesize($safe_file) > self::MAX_IMAGE_BYTES) {
        @unlink($safe_file);
        return new WP_Error('swi_output_type', 'Processed image has an unsupported format or size.');
    }

    $filename = sanitize_file_name(sanitize_title($title ?: 'imported-image') . '-' . wp_generate_password(6, false, false) . '.' . self::ALLOWED_MIMES[$safe_mime]);
    $file_array = array('name' => $filename, 'tmp_name' => $safe_file, 'type' => $safe_mime, 'size' => filesize($safe_file), 'error' => 0);

    require_once ABSPATH . 'wp-admin/includes/file.php';
    require_once ABSPATH . 'wp-admin/includes/media.php';
    require_once ABSPATH . 'wp-admin/includes/image.php';

    $attachment_id = media_handle_sideload($file_array, 0, sanitize_text_field($title));

    if (is_wp_error($attachment_id)) {
        if (file_exists($safe_file)) {
            @unlink($safe_file);
        }

        return $attachment_id;
    }

    wp_update_post(array('ID' => $attachment_id, 'post_author' => $author_id));
    update_post_meta($attachment_id, '_swi_imported_safe_image', 1);

    return $attachment_id;
}

private static function safe_download_image($url) {
    $url = esc_url_raw($url, array('http', 'https'));

    if (!$url || !self::is_public_http_url($url)) {
        return new WP_Error('swi_url', 'URL is invalid or points to a local/private destination.');
    }

    $current = $url;

    for ($i = 0; $i <= self::MAX_REDIRECTS; $i++) {
        if (!self::is_public_http_url($current)) {
            return new WP_Error('swi_redirect_url', 'Redirect destination is not allowed.');
        }

        $response = wp_safe_remote_get($current, array(
            'timeout' => 15,
            'redirection' => 0,
            'limit_response_size' => self::MAX_IMAGE_BYTES + 1,
            'headers' => array('Accept' => 'image/jpeg,image/png,image/webp'),
            'user-agent' => 'Safe-WXR-Importer/' . self::VERSION . '; ' . home_url('/'),
            'reject_unsafe_urls' => true,
        ));

        if (is_wp_error($response)) {
            return $response;
        }

        $code = (int) wp_remote_retrieve_response_code($response);

        if (in_array($code, array(301,302,303,307,308), true)) {
            if ($i >= self::MAX_REDIRECTS) {
                return new WP_Error('swi_redirect_limit', 'Too many redirects while downloading image.');
            }

            $location = wp_remote_retrieve_header($response, 'location');

            if (!$location) {
                return new WP_Error('swi_redirect_missing', 'Redirect did not include a destination.');
            }

            $current = WP_Http::make_absolute_url($location, $current);
            continue;
        }

        if ($code !== 200) {
            return new WP_Error('swi_http_status', 'Image server returned HTTP status ' . $code . '.');
        }

        $body = wp_remote_retrieve_body($response);

        if (!is_string($body) || $body === '' || strlen($body) > self::MAX_IMAGE_BYTES) {
            return new WP_Error('swi_size', 'Image is empty or exceeds the 12 MB limit.');
        }

        $tmp = wp_tempnam('swi-download');

        if (!$tmp) {
            return new WP_Error('swi_temp', 'Could not create a temporary download file.');
        }

        if (file_put_contents($tmp, $body, LOCK_EX) === false) {
            @unlink($tmp);
            return new WP_Error('swi_write', 'Could not save downloaded image.');
        }

        $detected = self::detect_image_mime($tmp);

        if (!$detected) {
            @unlink($tmp);
            return new WP_Error('swi_mime', 'Downloaded file is not an approved JPEG, PNG, or WebP image.');
        }

        return array('path' => $tmp, 'mime' => $detected);
    }

    return new WP_Error('swi_download', 'Image download failed.');
}

private static function detect_image_mime($path) {
    if (!is_file($path) || filesize($path) < 12 || filesize($path) > self::MAX_IMAGE_BYTES) {
        return false;
    }

    $finfo = function_exists('finfo_open') ? finfo_open(FILEINFO_MIME_TYPE) : false;
    $mime = $finfo ? finfo_file($finfo, $path) : '';

    if ($finfo) {
        finfo_close($finfo);
    }

    if (!isset(self::ALLOWED_MIMES[$mime])) {
        return false;
    }

    $info = @getimagesize($path);

    if (!$info || empty($info['mime']) || $info['mime'] !== $mime) {
        return false;
    }

    // Validate file signatures independently of the file extension and HTTP Content-Type
    $head = file_get_contents($path, false, null, 0, 16);

    if ($mime === 'image/jpeg' && substr((string)$head, 0, 3) !== "\xFF\xD8\xFF") {
        return false;
    }

    if ($mime === 'image/png' && substr((string)$head, 0, 8) !== "\x89PNG\r\n\x1A\n") {
        return false;
    }

    if ($mime === 'image/webp' && (substr((string)$head, 0, 4) !== 'RIFF' || substr((string)$head, 8, 4) !== 'WEBP')) {
        return false;
    }

    return $mime;
}

private static function is_public_http_url($url) {
    $parts = wp_parse_url($url);

    if (!$parts || empty($parts['scheme']) || empty($parts['host']) || !in_array(strtolower($parts['scheme']), array('http','https'), true)) {
        return false;
    }

    if (isset($parts['user']) || isset($parts['pass'])) {
        return false;
    }

    $host = strtolower(rtrim($parts['host'], '.'));

    if ($host === 'localhost' || substr($host, -10) === '.localhost' || substr($host, -6) === '.local' || substr($host, -4) === '.lan' || substr($host, -7) === '.internal') {
        return false;
    }

    if (filter_var($host, FILTER_VALIDATE_IP)) {
        return (bool) filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    // Resolve A and AAAA records where possible and reject any non-public answer
    $ips = array();

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

private static function safe_date($date) {
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
    wp_safe_redirect(add_query_arg(array('page' => 'safe-wxr-importer', 'swi_result' => rawurlencode($message)), admin_url('tools.php')));
    exit;
}
}

Safe_WXR_Importer::init();