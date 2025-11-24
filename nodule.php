<?php
// Исправлен путь
require_once __DIR__ . '/config.php';

function ReportIP_AbuseIPDB($ip, $category, $comment)
{
    // Используем константу вместо global (надёжнее)
    if (!defined('ABUSEIPDB_TOKEN')) {
        return;
    }
    $token = ABUSEIPDB_TOKEN;

    $url = "https://api.abuseipdb.com/api/v2/report";
    $postData = http_build_query([
        'ip' => $ip,
        'categories' => $category,
        'comment' => $comment
    ]);
    $headers = [
        "Key: " . $token,
        "Accept: application/json",
        "Content-Type: application/x-www-form-urlencoded",
        "User-Agent: Lenta-WAF/1.3"
    ];
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POSTFIELDS => $postData,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    curl_exec($ch);
    curl_close($ch);
}

function TelegramAlert($comment) {
    if (!defined('TELEGRAM_BOT_TOKEN') || !defined('ADMIN_CHAT_ID')) {
        return false;
    }
    $token_tg = TELEGRAM_BOT_TOKEN;
    $chat_id = ADMIN_CHAT_ID;
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    $ptr = @gethostbyaddr($ip) ?: 'Unknown';
    $isp_info = @file_get_contents("http://ip-api.com/json/{$ip}");
    $isp_data = json_decode($isp_info, true);
    $isp = $isp_data['isp'] ?? 'Unknown';
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? "https" : "http";
    $url = $protocol . "://" . ($_SERVER['HTTP_HOST'] ?? 'Unknown') . ($_SERVER['REQUEST_URI'] ?? '');
    $referer = $_SERVER['HTTP_REFERER'] ?? 'Direct/Unknown';
    $message = "🚨 Заблокирована попытка атаки\n";
    $message .= "IP: $ip\n";
    $message .= "PTR: $ptr\n";
    $message .= "ISP: $isp\n";
    $message .= "URL: $url\n";
    $message .= "REFERER: $referer\n";
    $message .= "COMMENT: $comment";
    $urlTelegram = "https://api.telegram.org/bot{$token_tg}/sendMessage";
    $postData = ['chat_id' => $chat_id,'text' => $message];
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $urlTelegram,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($postData),
                      CURLOPT_RETURNTRANSFER => true,
                      CURLOPT_TIMEOUT => 10,
                      CURLOPT_CONNECTTIMEOUT => 5,
                      CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $response = curl_exec($ch);
    curl_close($ch);
    return true;
}

function get_ip_info($ip) {
    if ($ip === '127.0.0.1' || $ip === '::1') {
        return ['country' => 'LOCAL', 'isp' => 'LOCAL'];
    }
    $url = "http://ip-api.com/json/{$ip}?fields=status,countryCode,isp";
    $context = stream_context_create(['http' => ['timeout' => 2]]);
    $response = @file_get_contents($url, false, $context);
    if ($response === false) {
        return ['country' => 'UNKNOWN', 'isp' => 'UNKNOWN'];
    }
    $data = json_decode($response, true);
    if ($data && $data['status'] === 'success') {
        return ['country' => $data['countryCode'], 'isp' => $data['isp']];
    }
    return ['country' => 'UNKNOWN', 'isp' => 'UNKNOWN'];
}
