<?php

if (defined('FIREWALL_LOADED')) return;
define('FIREWALL_LOADED', true);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/module.php';

/* ============================================================
 *   FAST PTR LOOKUP (UDP DNS сокет)
 *   ============================================================ */

function fast_ptr_lookup(string $ip, int $timeout_ms = 40): ?string {

    // IPv4 only
    if (strpos($ip, ':') !== false) return null;

    $parts = explode('.', $ip);
    if (count($parts) !== 4) return null;

    // Reverse
    $ptr_name = "{$parts[3]}.{$parts[2]}.{$parts[1]}.{$parts[0]}.in-addr.arpa";

    // DNS query header
    $query = pack('nnn', rand(1, 0xFFFF), 0x0100, 1);
    // QNAME: reversed IP + in-addr.arpa
    foreach (explode('.', $ptr_name) as $label) {
        $query .= chr(strlen($label)) . $label;
    }
    $query .= chr(0);
    // QTYPE PTR (12), QCLASS IN (1)
    $query .= pack('nn', 12, 1);

    $sock = @fsockopen("udp://1.1.1.1", 53, $errno, $err, $timeout_ms / 1000);
    if (!$sock) return null;

    stream_set_timeout($sock, 0, $timeout_ms * 1000);

    fwrite($sock, $query);
    $response = fread($sock, 512);
    fclose($sock);

    if (!$response || strlen($response) < 12) return null;

    // Skip DNS header
    $offset = 12;

    // Skip QNAME
    while (true) {
        $len = ord($response[$offset]);
        if ($len === 0) {
            $offset++;
            break;
        }
        $offset += $len + 1;
    }

    // Skip QTYPE + QCLASS
    $offset += 4;

    // Answer NAME pointer
    if ($offset + 12 > strlen($response)) return null;
    $offset += 2;

    // TYPE, CLASS, TTL, RDLENGTH
    $offset += 4 + 4; // TYPE+CLASS + TTL
    $rdlength = unpack('n', substr($response, $offset, 2))[1];
    $offset += 2;

    // Parse RDATA (labels)
    $end = $offset + $rdlength;
    $labels = [];

    while ($offset < $end) {
        $len = ord($response[$offset]);

        if ($len === 0) break;

        // Pointer
        if (($len & 0xC0) === 0xC0) {
            $ptrOffset = unpack('n', substr($response, $offset, 2))[1] & 0x3FFF;
            $labels[] = dns_read_name($response, $ptrOffset);
            break;
        }
        $offset++;
        $labels[] = substr($response, $offset, $len);
        $offset += $len;
    }
    return implode('.', $labels);
}
function dns_read_name(string $packet, int $offset): string {
    $labels = [];

    while (true) {
        $len = ord($packet[$offset]);
        if ($len === 0) break;
        if (($len & 0xC0) === 0xC0) {
            $ptr = unpack('n', substr($packet, $offset, 2))[1] & 0x3FFF;
            $labels[] = dns_read_name($packet, $ptr);
            break;
        }
        $offset++;
        $labels[] = substr($packet, $offset, $len);
        $offset += $len;
    }
    return implode('.', $labels);
}
function FW_403($reason) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

    static $messages = [
        'Fake_device'       => ['19,17','Плохой бот, косит под реальные устройства.','Очередная атака ботов'],
        'fake-yandex-bot'   => ['19,17','Фейковый Яндекс бот','Фейк бот: Яндекс'],
        'fake-google-bot'   => ['19,17','Фейковый Google бот','Фейк бот: Google'],
        'fake-bing-bot'     => ['19,17','Фейковый Bing бот','Фейк бот: Bing'],
        'wpcron_badagent'   => ['21','wp-cron плохой UA','wp-cron заблокирован'],
        'bad-ua'            => ['21','Плохой UA','Сканер — школьники'],
        'client_locker'     => [null,null,'Бот из черного списка'],
        'empty-or-dash-UA'  => ['19,21','UA пустой','Пустой UA'],
        'tryscan_rsd'       => ['21','RSD скан','Попытка XML-RPC RSD']
    ];

    if (isset($messages[$reason])) {
        [$cat,$comment,$tg] = $messages[$reason];
        if ($cat) ReportIP_AbuseIPDB($ip, $cat, $comment);
        TelegramAlert($tg);
    } elseif (str_starts_with($reason, 'blocked-')) {
        TelegramAlert("Блокировка: $reason");
    }

    header('HTTP/1.1 403 Forbidden');
    exit;
}
$req_uri = $_SERVER['REQUEST_URI'] ?? '/';
$path    = parse_url($req_uri, PHP_URL_PATH);
$ua      = $_SERVER['HTTP_USER_AGENT'] ?? '';
$ua_lc   = strtolower($ua);
if ($ua === '' || $ua === '-' || trim($ua) === '')
    FW_403('empty-or-dash-UA');
foreach ([
    '/phpmyadmin','/phpMyAdmin','/admin','/wp-config.php','/.env','/backup.zip',
    '/backup.tar.gz','/readme.html','/install.php','/xmlrpc.php','/waf/config.php'
] as $u) {
    if (str_starts_with($path, $u)) FW_403('blocked-uri');
}
if ($req_uri === '/xmlrpc.php?rsd')
    FW_403('tryscan_rsd');

/* wp-cron */
if (str_contains($req_uri, '/wp-cron.php')) {
    if (!preg_match('#^WordPress/[\d\.]+(; https?://\S+)?$#i', $ua))
        FW_403('wpcron_badagent');
}

/* security scanners */
foreach (['acunetix','netsparker','nikto','wpscan','nessus','openvas',
    'sqlmap','arachni','whatweb','nmap','masscan'] as $s) {
    if (str_contains($ua_lc, $s)) FW_403('security-scanner');
    }

    /* плохие агенты */
    foreach (['axios','wget','aiohttp','go-http-client','phantomjs','python',
        'gnu-tools','mra58n','sm-g900p'] as $s) {
        if (str_contains($ua_lc, $s)) FW_403('bad-ua');
        }

        /* фейковые устройства */
        if (strpbrk($ua, 'CWSAFUXMP') !== false) {
            if (empty($_SERVER['HTTP_ACCEPT']) ||
                empty($_SERVER['HTTP_ACCEPT_ENCODING']) ||
                empty($_SERVER['HTTP_ACCEPT_LANGUAGE']))
                FW_403('Fake_device');
        }

        /* ============================================================
         *   REFERER RULES
         *   ============================================================ */

        $ref = strtolower($_SERVER['HTTP_REFERER'] ?? '');

        if ($ref !== '') {

            static $ref_rules = [
                ['RU','facebook.com',1],
                ['RU','bigmir.net',1],
                ['RU','google.com',1],
                ['RU','youtube.com',1],
                ['RU','yandex.kz',1],
                ['RU','yandex.by',1],
                ['RU','meta.ua',0],
                ['AZ','vk.com',1],
                ['AZ','yandex.ru',1],
                ['AZ','yandex.kz',1],
                ['UA','vk.com',1],
                ['UA','mail.ru',1],
                ['UA','dzen.ru',1],
                ['ALL','yandex.ua',1],
                ['ALL','http://facebook.com',1],
                ['ALL','http://instagram.com',1],
                ['ALL','https://www.google.com/search?q=site:',1],
            ];

            $ref_starts = [
                'http://facebook.com','http://instagram.com','http://meta.ua'
            ];

            foreach ($ref_rules as [$c,$needle,$type]) {
                if (!str_contains($ref, $needle)) continue;

                if ($c === 'ALL') FW_403("blocked-ref-all");

                if ($type && $country === $c)  FW_403("blocked-$c-$needle");
                if (!$type && $country !== $c) FW_403("blocked-not-$c-$needle");
            }

            foreach ($ref_starts as $b) {
                if (str_starts_with($ref, $b)) FW_403('blocked-referer');
            }
        }

        /* ============================================================
         *   IP / ISP
         *   ============================================================ */

        $ip = $_SERVER['REMOTE_ADDR'];
        $info = get_ip_info($ip);
        $country = $info['country'];
        $isp = strtolower($info['isp']);

        foreach (['beretika llc','smart ape'] as $bad) {
            if (str_contains($isp, $bad)) FW_403('blocked-isp');
        }

        /* ============================================================
         *   BOT VALIDATION (FAST DNS)
         *   ============================================================ */

        function FW_check_bot($ua_lc, $name, $domains, $reason) {

            if (!str_contains($ua_lc, $name)) return;

            $ip  = $_SERVER['REMOTE_ADDR'];
            $ptr = fast_ptr_lookup($ip);

            if (!$ptr) FW_403($reason);

            foreach ($domains as $d) {
                if (str_ends_with($ptr, $d)) {
                    // Комплексная обратная проверка
                    if (gethostbyname($ptr) === $ip)
                        return;
                }
            }

            FW_403($reason);
        }

        FW_check_bot($ua_lc, 'googlebot', ['.googlebot.com','.google.com'], 'fake-google-bot');
        FW_check_bot($ua_lc, 'yandexbot', ['.spider.yandex.ru','.spider.yandex.net','.spider.yandex.com'], 'fake-yandex-bot');
        FW_check_bot($ua_lc, 'bingbot',   ['.bing.com','.search.msn.com'], 'fake-bing-bot');

        ?>
