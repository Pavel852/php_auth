<?php
/**
 * auth.php - Simple Authentication System
 * Version: 1.1
 * Release Date: 10/2024
 * Author: PB
 * Email: pavel.bartos.pb@gmail.com
 *
 * Popis Funkcí:
 * - auth_settings($params): Nastavení konfigurace knihovny pomocí řetězce s parametry.
 * - auth_version(): Vrací aktuální verzi systému autentizace.
 * - generateNumericPassword($length): Generuje náhodné číselné heslo.
 * - generateToken(): Generuje náhodný token.
 * - auth_register($username, $password, $userid, $email): Registrace nového uživatele.
 * - auth_login($identifier, $password, $user_data): Přihlášení uživatele.
 * - auth_logout(): Odhlášení uživatele.
 * - auth_request_password_reset($email, $user_data): Žádost o resetování hesla.
 * - auth_reset_password($token, $new_password, &$user_data): Resetování hesla pomocí tokenu.
 * - auth_verify_email($token, &$user_data): Verifikace emailu pomocí tokenu.
 * - auth_get_user(): Získání aktuálně přihlášeného uživatele.
 * - auth_is_logged_in(): Kontrola, zda je uživatel přihlášen.
 */

// Proměnná pro verzi na začátku souboru
$auth_version = '1.1';

// Inicializace nastavení
$auth_settings = [];

/**
 * Funkce pro nastavení konfigurace
 *
 * @param string $params Parametry nastavení ve formátu "klíč=hodnota, ..."
 * @return void
 */
function auth_settings($params = "") {
    global $auth_settings;

    // Výchozí hodnoty
    $default_settings = [
        'email_verification' => true,
        'numeric_password_length' => 6,
        'reset_token_expiry' => 3600,
        'verification_token_expiry' => 86400,
        'passwd_verification' => false,
    ];

    // Nastavení výchozích hodnot
    $auth_settings = $default_settings;

    // Pokud jsou parametry předány jako string
    if (is_string($params) && !empty($params)) {
        // Rozdělíme parametry podle čárky
        $pairs = explode(',', $params);
        foreach ($pairs as $pair) {
            // Rozdělíme klíč a hodnotu podle rovná se
            $key_value = explode('=', trim($pair));
            if (count($key_value) == 2) {
                $key = trim($key_value[0]);
                $value = trim($key_value[1]);

                // Konvertování hodnot na správné typy
                if (in_array($key, ['email_verification', 'passwd_verification'])) {
                    $value = filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
                    if ($value === null) continue; // Neplatná hodnota, přeskočíme
                } elseif (in_array($key, ['numeric_password_length', 'reset_token_expiry', 'verification_token_expiry'])) {
                    $value = intval($value);
                }

                // Ověření, že `passwd_verification` může být nastaveno jen pokud `email_verification=true`
                if ($key === 'passwd_verification') {
                    if ($value === true && $auth_settings['email_verification'] !== true) {
                        // Nelze nastavit `passwd_verification` pokud `email_verification` není true
                        continue;
                    }
                }

                // Nastavení hodnoty
                if (array_key_exists($key, $auth_settings)) {
                    $auth_settings[$key] = $value;
                }
            }
        }
    }

    // Znovu ověříme, že `passwd_verification` je nastavena pouze pokud `email_verification=true`
    if ($auth_settings['passwd_verification'] && !$auth_settings['email_verification']) {
        $auth_settings['passwd_verification'] = false;
    }
}

// Inicializace nastavení s výchozími hodnotami
auth_settings();

/**
 * Funkce auth_version
 *
 * Vrací pouze verzi systému autentizace jako řetězec.
 *
 * @return string
 */
function auth_version() {
    global $auth_version;
    return $auth_version;
}

// Inicializace session
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Pomocné funkce

/**
 * Generuje náhodné číselné heslo.
 *
 * @param int $length Počet číslic.
 * @return string
 */
function generateNumericPassword($length = 6) {
    $password = '';
    for ($i = 0; $i < $length; $i++) {
        $password .= mt_rand(0, 9);
    }
    return $password;
}

/**
 * Generuje náhodný token.
 *
 * @return string
 */
function generateToken() {
    return bin2hex(random_bytes(16)); // 32 znaků
}

/**
 * Registrace uživatele.
 *
 * @param string|array $username Uživatelské jméno nebo pole s údaji.
 * @param string|null $password Heslo (nepovinné, pokud je emailová verifikace povolena).
 * @param mixed $userid ID uživatele (nepovinné).
 * @param string|null $email Email uživatele (nepovinné).
 * @return array|string Vrací pole s uživatelskými údaji nebo chybovou zprávu.
 */
function auth_register($username, $password = null, $userid = null, $email = null) {
    global $auth_settings;

    // Zpracování vstupů
    if (is_array($username)) {
        $data = $username;
    } else {
        $data = [
            'username' => $username,
            'password' => $password,
            'userid' => $userid,
            'email' => $email,
        ];
    }

    // Validace povinných polí
    if (empty($data['username'])) {
        return "Username is required.";
    }

    if ($auth_settings['email_verification'] && empty($data['email'])) {
        return "Email is required for email verification.";
    }

    if (!$auth_settings['email_verification'] && empty($data['password'])) {
        return "Password is required.";
    }

    // Pokud je emailová verifikace povolena, generujeme číselné heslo
    if ($auth_settings['email_verification']) {
        $numeric_password = generateNumericPassword($auth_settings['numeric_password_length']);
        $hashed_password = password_hash($numeric_password, PASSWORD_DEFAULT);
        $is_verified = false;
        $verification_token = generateToken();
        $verification_expires = time() + $auth_settings['verification_token_expiry'];
    } else {
        // Hashování hesla pomocí password_hash()
        $hashed_password = password_hash($data['password'], PASSWORD_DEFAULT);
        $is_verified = true;
        $verification_token = null;
        $verification_expires = null;
    }

    // Vytvoření uživatelského pole
    $user = [
        'username' => $data['username'],
        'password' => $hashed_password,
        'userid' => $data['userid'] ?? null,
        'email' => $data['email'] ?? null,
        'is_verified' => $is_verified,
        'verification_token' => $verification_token,
        'verification_expires' => $verification_expires,
        'created_at' => time(),
    ];

    // Odeslání číselného hesla uživateli (např. emailem)
    if ($auth_settings['email_verification']) {
        // Zde by mělo dojít k odeslání $numeric_password uživateli
        // Například: send_email($user['email'], 'Your temporary password', $numeric_password);
        // Pro účely této funkce můžeme vrátit $numeric_password jako součást výsledku
        $user['temp_password'] = $numeric_password;
    }

    // Vrácení uživatelských údajů
    return $user;
}

/**
 * Přihlášení uživatele.
 *
 * @param string|int $identifier Uživatelské jméno nebo UserID.
 * @param string $password Heslo.
 * @param array $user_data Pole s uživatelskými údaji.
 * @return bool|string Vrací true při úspěchu, jinak chybovou zprávu.
 */
function auth_login($identifier, $password, $user_data) {
    global $auth_settings;

    // Identifikace uživatele
    if (is_numeric($identifier)) {
        if ($user_data['userid'] != $identifier) {
            return "Invalid credentials.";
        }
    } else {
        if ($user_data['username'] !== $identifier) {
            return "Invalid credentials.";
        }
    }

    // Kontrola emailové verifikace
    if ($auth_settings['email_verification'] && !$user_data['is_verified']) {
        return "Please verify your email before logging in.";
    }

    // Ověření hesla pomocí password_verify()
    if (!password_verify($password, $user_data['password'])) {
        return "Invalid credentials.";
    }

    // Nastavení session
    $_SESSION['user_id'] = $user_data['userid'] ?? $user_data['username'];
    $_SESSION['username'] = $user_data['username'];

    return true;
}

/**
 * Odhlášení uživatele.
 *
 * @return void
 */
function auth_logout() {
    session_unset();
    session_destroy();
}

/**
 * Žádost o resetování hesla.
 *
 * @param string $email Email uživatele.
 * @param array &$user_data Pole s uživatelskými údaji (předává se referencí pro aktualizaci).
 * @return array|string Vrací pole s reset tokenem a expirací nebo chybovou zprávu.
 */
function auth_request_password_reset($email, &$user_data) {
    global $auth_settings;

    // Kontrola emailu
    if ($user_data['email'] !== $email) {
        return "Email not found.";
    }

    // Generování reset tokenu
    $reset_token = generateToken();
    $reset_expires = time() + $auth_settings['reset_token_expiry'];

    // Aktualizace uživatelských údajů
    $user_data['password_reset_token'] = $reset_token;
    $user_data['password_reset_expires'] = $reset_expires;

    // Odeslání reset tokenu uživateli (např. emailem)
    // Například: send_email($user_data['email'], 'Password Reset', 'Your reset token is: ' . $reset_token);

    // Vrácení reset tokenu a expirace (pro testovací účely)
    return [
        'reset_token' => $reset_token,
        'reset_expires' => $reset_expires,
    ];
}

/**
 * Resetování hesla.
 *
 * @param string $token Reset token.
 * @param string $new_password Nové heslo.
 * @param array &$user_data Pole s uživatelskými údaji (předává se referencí pro aktualizaci).
 * @return bool|string Vrací true při úspěchu, jinak chybovou zprávu.
 */
function auth_reset_password($token, $new_password, &$user_data) {
    global $auth_settings;

    // Kontrola reset tokenu
    if (
        (!isset($user_data['password_reset_token']) || $user_data['password_reset_token'] !== $token) &&
        (!isset($user_data['set_password_token']) || $user_data['set_password_token'] !== $token)
    ) {
        return "Invalid reset token.";
    }

    // Kontrola expirace tokenu
    $expires = $user_data['password_reset_expires'] ?? $user_data['set_password_expires'] ?? 0;
    if ($expires < time()) {
        return "Reset token has expired.";
    }

    // Hashování nového hesla
    $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
    $user_data['password'] = $hashed_password;

    // Vymazání reset tokenu a expirace
    unset($user_data['password_reset_token']);
    unset($user_data['password_reset_expires']);
    unset($user_data['set_password_token']);
    unset($user_data['set_password_expires']);

    return true;
}

/**
 * Verifikace emailu.
 *
 * @param string $token Verifikační token.
 * @param array &$user_data Pole s uživatelskými údaji (předává se referencí pro aktualizaci).
 * @return array|bool|string Vrací aktualizované uživatelské údaje nebo chybovou zprávu.
 */
function auth_verify_email($token, &$user_data) {
    global $auth_settings;

    // Kontrola verifikačního tokenu
    if (!isset($user_data['verification_token']) || $user_data['verification_token'] !== $token) {
        return "Invalid verification token.";
    }

    // Kontrola expirace tokenu
    if (!isset($user_data['verification_expires']) || $user_data['verification_expires'] < time()) {
        return "Verification token has expired.";
    }

    // Nastavení uživatele jako ověřeného
    $user_data['is_verified'] = true;
    unset($user_data['verification_token']);
    unset($user_data['verification_expires']);

    // Pokud je povolena verifikace hesla, uživatel musí nastavit své heslo
    if ($auth_settings['passwd_verification']) {
        // Generování nového tokenu pro nastavení hesla
        $set_password_token = generateToken();
        $set_password_expires = time() + $auth_settings['reset_token_expiry'];
        $user_data['set_password_token'] = $set_password_token;
        $user_data['set_password_expires'] = $set_password_expires;

        // Odeslání tokenu pro nastavení hesla uživateli (např. emailem)
        // Například: send_email($user_data['email'], 'Set Your Password', 'Your token is: ' . $set_password_token);

        // Vrácení tokenu pro nastavení hesla (pro testovací účely)
        return [
            'is_verified' => true,
            'set_password_token' => $set_password_token,
            'set_password_expires' => $set_password_expires,
        ];
    }

    return true;
}

/**
 * Funkce pro získání aktuálně přihlášeného uživatele.
 *
 * @return string|null
 */
function auth_get_user() {
    return $_SESSION['username'] ?? null;
}

/**
 * Funkce pro kontrolu, zda je uživatel přihlášen.
 *
 * @return bool
 */
function auth_is_logged_in() {
    return isset($_SESSION['user_id']);
}

