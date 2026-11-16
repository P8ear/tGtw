<?php
header('Content-Type: application/json; charset=utf-8');

// 1. Настройки безопасности
$secretKey = 'QWERTY!@#$%^QWERTY';
$allowedIp = ''; // ВПИШИТЕ IP ВАШЕГО ОСНОВНОГО СЕРВЕРА (или оставьте пустым '', если IP динамический)

// Проверка IP-адреса отправителя
if (!empty($allowedIp) && ($_SERVER['REMOTE_ADDR'] ?? '') !== $allowedIp) {
    http_response_code(403);
    echo json_encode(['ok' => false, 'description' => 'Forbidden IP: ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown')]);
    exit;
}

// Получаем сырое тело запроса и заголовки подписи
$rawBody = file_get_contents('php://input');
$clientTimestamp = (int)($_SERVER['HTTP_X_TIMESTAMP'] ?? 0);
$clientSignature = $_SERVER['HTTP_X_SIGNATURE'] ?? '';

// 2. Проверка актуальности запроса (окно жизни запроса — 30 секунд)
if (abs(time() - $clientTimestamp) > 30) {
    http_response_code(403);
    echo json_encode(['ok' => false, 'description' => 'Request expired']);
    exit;
}

// 3. Проверка криптографической подписи HMAC-SHA256
$expectedSignature = hash_hmac('sha256', $clientTimestamp . '.' . $rawBody, $secretKey);
if (!hash_equals($expectedSignature, $clientSignature)) {
    http_response_code(403);
    echo json_encode(['ok' => false, 'description' => 'Invalid signature']);
    exit;
}

$input = json_decode($rawBody, true);
$token = trim($input['token'] ?? '');
$method = trim($input['method'] ?? '');
$params = $input['params'] ?? [];

// 4. Белый список разрешенных методов Telegram API (защита от злоупотреблений)
$allowedMethods = ['getChatMember', 'getMe', 'sendMessage'];
if (!in_array($method, $allowedMethods, true)) {
    http_response_code(403);
    echo json_encode(['ok' => false, 'description' => 'Method not allowed']);
    exit;
}

if (empty($token)) {
    echo json_encode(['ok' => false, 'description' => 'Missing token']);
    exit;
}

// 5. Выполнение запроса к Telegram
$apiBase = 'https://' . 'api.telegram.org' . '/bot';
$url = $apiBase . $token . '/' . $method;

if (!empty($params) && is_array($params)) {
    $url .= '?' . http_build_query($params);
}

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

$response = curl_exec($ch);
$error = curl_error($ch);
curl_close($ch);

if ($response === false) {
    echo json_encode(['ok' => false, 'description' => 'Gateway cURL error: ' . $error]);
} else {
    echo $response;
}
