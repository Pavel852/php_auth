<?php
namespace Auth;

/**
 * Auth.php - Simple Authentication System
 * Version: 2.0
 * Release Date: 11/2024
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
 * - auth_debug(): Výpis informací o registrovaných uživatelích pro debugování.
 */

class Auth {
    // Proměnná pro verzi
    private static $auth_version = '1.1';

    // Inicializace nastavení
    private static $auth_settings = [];

    // Pole pro uchování registrovaných uživatelů
    private static $registered_users = [];

    // Inicializace session
    public static function initSession() {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
    }

    /**
     * Funkce pro nastavení konfigurace
     *
     * @param string $params Parametry nastavení ve formátu "klíč=hodnota, ..."
     * @return void
     */
    public static function auth_settings($params = "") {
        // Výchozí hodnoty
        $default_settings = [
            'email_verification' => true,
            'numeric_password_length' => 6,
            'reset_token_expiry' => 3600,
            'verification_token_expiry' => 86400,
            'passwd_verification' => false,
        ];

        // Nastavení výchozích hodnot
        self::$auth_settings = $default_settings;

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
                        if ($value === true && self::$auth_settings['email_verification'] !== true) {
                            // Nelze nastavit `passwd_verification` pokud `email_verification` není true
                            continue;
                        }
                    }

                    // Nastavení hodnoty
                    if (array_key_exists($key, self::$auth_settings)) {
                        self::$auth_settings[$key] = $value;
                    }
                }
            }
        }

        // Znovu ověříme, že `passwd_verification` je nastavena pouze pokud `email_verification=true`
        if (self::$auth_settings['passwd_verification'] && !self::$auth_settings['email_verification']) {
            self::$auth_settings['passwd_verification'] = false;
        }
    }

    /**
     * Funkce auth_version
     *
     * Vrací pouze verzi systému autentizace jako řetězec.
     *
     * @return string
     */
    public static function auth_version() {
        return self::$auth_version;
    }

    /**
     * Generuje náhodné číselné heslo.
     *
     * @param int $length Počet číslic.
     * @return string
     */
    public static function generateNumericPassword($length = 6) {
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
    public static function generateToken() {
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
    public static function auth_register($username, $password = null, $userid = null, $email = null) {
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

        if (self::$auth_settings['email_verification'] && empty($data['email'])) {
            return "Email is required for email verification.";
        }

        if (!self::$auth_settings['email_verification'] && empty($data['password'])) {
            return "Password is required.";
        }

        // Pokud je emailová verifikace povolena, generujeme číselné heslo
        if (self::$auth_settings['email_verification']) {
            $numeric_password = self::generateNumericPassword(self::$auth_settings['numeric_password_length']);
            $hashed_password = password_hash($numeric_password, PASSWORD_DEFAULT);
            $is_verified = false;
            $verification_token = self::generateToken();
            $verification_expires = time() + self::$auth_settings['verification_token_expiry'];
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
        if (self::$auth_settings['email_verification']) {
            // Zde by mělo dojít k odeslání $numeric_password uživateli
            // Například: send_email($user['email'], 'Your temporary password', $numeric_password);
            // Pro účely této funkce můžeme vrátit $numeric_password jako součást výsledku
            $user['temp_password'] = $numeric_password;
        }

        // Uložení uživatele do pole registrovaných uživatelů
        self::$registered_users[] = $user;

        // Vrácení uživatelských údajů
        return $user;
    }

    /**
     * Přihlášení uživatele.
     *
     * @param string|int $identifier Uživatelské jméno nebo UserID.
     * @param string $password Heslo.
     * @return bool|string Vrací true při úspěchu, jinak chybovou zprávu.
     */
    public static function auth_login($identifier, $password) {
        // Hledání uživatele
        $user_data = null;
        foreach (self::$registered_users as $user) {
            if ($user['username'] === $identifier || $user['userid'] === $identifier) {
                $user_data = $user;
                break;
            }
        }

        if (!$user_data) {
            return "Invalid credentials.";
        }

        // Kontrola emailové verifikace
        if (self::$auth_settings['email_verification'] && !$user_data['is_verified']) {
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
    public static function auth_logout() {
        session_unset();
        session_destroy();
    }

    /**
     * Žádost o resetování hesla.
     *
     * @param string $email Email uživatele.
     * @return array|string Vrací pole s reset tokenem a expirací nebo chybovou zprávu.
     */
    public static function auth_request_password_reset($email) {
        // Hledání uživatele
        $user_data = null;
        foreach (self::$registered_users as &$user) {
            if ($user['email'] === $email) {
                $user_data = &$user;
                break;
            }
        }

        if (!$user_data) {
            return "Email not found.";
        }

        // Generování reset tokenu
        $reset_token = self::generateToken();
        $reset_expires = time() + self::$auth_settings['reset_token_expiry'];

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
     * @return bool|string Vrací true při úspěchu, jinak chybovou zprávu.
     */
    public static function auth_reset_password($token, $new_password) {
        // Hledání uživatele
        $user_data = null;
        foreach (self::$registered_users as &$user) {
            if (
                (isset($user['password_reset_token']) && $user['password_reset_token'] === $token) ||
                (isset($user['set_password_token']) && $user['set_password_token'] === $token)
            ) {
                $user_data = &$user;
                break;
            }
        }

        if (!$user_data) {
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
     * @return array|bool|string Vrací aktualizované uživatelské údaje nebo chybovou zprávu.
     */
    public static function auth_verify_email($token) {
        // Hledání uživatele
        $user_data = null;
        foreach (self::$registered_users as &$user) {
            if (isset($user['verification_token']) && $user['verification_token'] === $token) {
                $user_data = &$user;
                break;
            }
        }

        if (!$user_data) {
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
        if (self::$auth_settings['passwd_verification']) {
            // Generování nového tokenu pro nastavení hesla
            $set_password_token = self::generateToken();
            $set_password_expires = time() + self::$auth_settings['reset_token_expiry'];
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
    public static function auth_get_user() {
        return $_SESSION['username'] ?? null;
    }

    /**
     * Funkce pro kontrolu, zda je uživatel přihlášen.
     *
     * @return bool
     */
    public static function auth_is_logged_in() {
        return isset($_SESSION['user_id']);
    }

    /**
     * Funkce pro debugování - výpis registrovaných uživatelů.
     *
     * @return void
     */
    public static function auth_debug() {
        echo '<hr>';
        echo '<div>';
        echo '<a href="#" onclick="var el=document.getElementById(\'auth_debug_info\'); if(el.style.display==\'none\'){el.style.display=\'block\';}else{el.style.display=\'none\';} return false;">->auth debug</a>';
        echo '<div id="auth_debug_info" style="display:none;">';

        foreach (self::$registered_users as $user) {
            $user_info = $user;
            $user_info['password'] = '***';
            echo '<pre>';
            print_r($user_info);
            echo '</pre>';
        }

        echo '</div>';
        echo '</div>';
    }
}

// Inicializace nastavení a session
Auth::auth_settings();
Auth::initSession();

