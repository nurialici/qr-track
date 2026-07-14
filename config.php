<?php
declare(strict_types=1);

// --- AUTHENTICATION SETTINGS ---
define('ADMIN_USER', 'admin');
define('ADMIN_PASS', 'change_me'); // Lütfen bu şifreyi değiştirin

// --- API SETTINGS ---
define('API_KEY', 'change_me_to_a_random_string'); // Güvenliğiniz için rastgele bir metin girin

// --- SITE SETTINGS ---
// Dokploy üzerindeki domaininizi otomatik algılar. Manuel yazmak isterseniz 'https://domaininiz.com' şeklinde de değiştirebilirsiniz.
define('BASE_URL', (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://" . ($_SERVER['HTTP_HOST'] ?? 'localhost'));

// --- DOKPLOY İÇİN AYARLANMIŞ KESİN YOLLAR ---
define('DB_PATH',  __DIR__ . '/storage_db/tuxxin_qr.sqlite');
define('LOGO_DIR', __DIR__ . '/storage_tmp');

define('TIMEZONE',   'Europe/Istanbul'); // Türkiye saat dilimine ayarlandı
define('THEME_PATH', __DIR__ . '/themes');

// --- NETWORK SETTINGS ---
define('USE_CLOUDFLARE_TUNNEL', false);

// --- DISABLED QR CODE PAGE ---
define('DISABLED_REDIRECT_URL', '');

// --- API RATE THROTTLING ---
define('API_THROTTLE_ENABLED', true);
define('API_THROTTLE_LIMIT',  60);   
define('API_THROTTLE_WINDOW', 60);   

// --- SESSION SETTINGS ---
define('SESSION_LIFETIME', 7200);

// =============================================================================
// END OF CONFIGURATION — do not edit below this line
// =============================================================================

function require_auth() {
    if (session_status() === PHP_SESSION_NONE) session_start();

    if (isset($_SESSION['last_active']) && (time() - $_SESSION['last_active']) > SESSION_LIFETIME) {
        session_unset();
        session_destroy();
        header("Location: " . BASE_URL . "/login.php");
        exit;
    }
    $_SESSION['last_active'] = time();

    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        header("Location: " . BASE_URL . "/login.php");
        exit;
    }
}

function csrf_token(): string {
    if (session_status() === PHP_SESSION_NONE) session_start();
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf(): void {
    $token = $_POST['csrf_token'] ?? '';
    if (!hash_equals(csrf_token(), $token)) {
        http_response_code(403);
        die('Invalid request (CSRF check failed).');
    }
}

function purge_old_tokens($db) {
    $db->exec("DELETE FROM api_tokens WHERE expires_at < datetime('now')");
}

// --- DATABASE CONNECTION ---
$dbDir  = dirname(DB_PATH);
$dbFile = DB_PATH;

if ((!is_dir($dbDir) || !is_writable($dbDir)) || (file_exists($dbFile) && !is_writable($dbFile))) {
    exit("Database Permission Error: PHP cannot write to $dbDir. Check that the directory exists and is writable by the web server.");
}

try {
    $db = new PDO('sqlite:' . DB_PATH);
    $db->setAttribute(PDO::ATTR_ERRMODE,            PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    $db->exec("CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT UNIQUE,
        title TEXT,
        type TEXT,
        target_data TEXT,
        logo_path TEXT DEFAULT NULL,
        is_active INTEGER DEFAULT 1,
        is_deleted INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");

    $db->exec("CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_uuid TEXT,
        ip_address TEXT,
        user_agent TEXT,
        scan_status TEXT DEFAULT 'success',
        scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(product_uuid) REFERENCES products(uuid)
    )");

    $columns = $db->query("PRAGMA table_info(scans)")->fetchAll(PDO::FETCH_COLUMN, 1);
    if (!in_array('geo_city', $columns)) {
        $db->exec("ALTER TABLE scans ADD COLUMN geo_city TEXT");
        $db->exec("ALTER TABLE scans ADD COLUMN geo_region TEXT");
        $db->exec("ALTER TABLE scans ADD COLUMN geo_country TEXT");
        $db->exec("ALTER TABLE scans ADD COLUMN geo_isp TEXT");
    }

    $db->exec("CREATE TABLE IF NOT EXISTS api_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT UNIQUE,
        product_uuid TEXT,
        expires_at DATETIME
    )");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_api_token ON api_tokens(token)");

    $db->exec("CREATE TABLE IF NOT EXISTS rate_limit (
        ip TEXT PRIMARY KEY,
        window_start INTEGER NOT NULL,
        request_count INTEGER NOT NULL DEFAULT 1
    )");

} catch (PDOException $e) {
    die("Database Error: " . $e->getMessage());
}
