<?php
// Načtení knihovny auth.php
require_once 'auth.php';

// Nastavení knihovny s povoleným emailovým ověřením
auth_settings('email_verification=true,passwd_verification=false');

// Inicializace session
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Inicializace uživatelů
if (!isset($_SESSION['users'])) {
    $_SESSION['users'] = [];
}

// Inicializace zprávy
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register'])) {
    // Uživatelský vstup
    $username = $_POST['username'] ?? '';
    $email = $_POST['email'] ?? '';

    // Registrace nového uživatele
    $registration = auth_register($username, null, null, $email);

    if (is_array($registration)) {
        // Uložení uživatelských dat do session
        $_SESSION['users'][$username] = $registration;

        // Odeslání verifikačního emailu s tokenem
        $verification_link = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'] . '?action=verify&token=' . $registration['verification_token'] . '&username=' . urlencode($username);
        $subject = 'Ověření emailu';
        $message_email = "Klikněte na následující odkaz pro ověření vašeho emailu:\n$verification_link";
        // mail($email, $subject, $message_email); // Odkomentujte pro odeslání emailu

        $message = "Registrace proběhla úspěšně. Zkontrolujte svůj email pro ověření.\n\n$verification_link"; // Pro testování zobrazíme odkaz
    } else {
        $message = "Chyba při registraci: " . $registration;
    }
}

if (isset($_GET['action']) && $_GET['action'] === 'verify' && isset($_GET['token']) && isset($_GET['username'])) {
    $token = $_GET['token'];
    $username = $_GET['username'];

    // Načtení uživatelských dat
    if (isset($_SESSION['users'][$username])) {
        $user_data = &$_SESSION['users'][$username];
        $verification_result = auth_verify_email($token, $user_data);

        if ($verification_result === true) {
            $message = "Email byl úspěšně ověřen. Nyní se můžete přihlásit.";

            // Přesměrování na přihlašovací část
            header('Location: ' . $_SERVER['PHP_SELF'] . '?action=login');
            exit();
        } else {
            $message = "Chyba při ověření emailu: " . $verification_result;
        }
    } else {
        $message = "Uživatel nenalezen.";
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    // Uživatelský vstup
    $input_username = $_POST['username'] ?? '';
    $input_password = $_POST['password'] ?? '';

    // Validace vstupu
    if (empty($input_username) || empty($input_password)) {
        $message = 'Prosím vyplňte obě pole.';
    } else {
        // Pokus o přihlášení
        if (isset($_SESSION['users'][$input_username])) {
            $user_data = $_SESSION['users'][$input_username];
            $input_password = $user_data['temp_password'] ?? $input_password; // Použijeme dočasné heslo, pokud existuje
            $result = auth_login($input_username, $input_password, $user_data);

            if ($result === true) {
                $message = "Přihlášení bylo úspěšné. Vítejte, " . htmlspecialchars(auth_get_user()) . "!";
            } else {
                $message = "Chyba při přihlášení: " . $result;
            }
        } else {
            $message = 'Uživatel neexistuje.';
        }
    }
}

if (isset($_GET['logout'])) {
    auth_logout();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit();
}
?>
<!DOCTYPE html>
<html lang="cs">
<head>
    <meta charset="UTF-8">
    <title>Registrace a přihlášení</title>
</head>
<body>
    <h1>Registrace s ověřením emailu</h1>
    <?php if (!empty($message)): ?>
        <p><?php echo nl2br(htmlspecialchars($message)); ?></p>
    <?php endif; ?>
    <?php if (!auth_is_logged_in()): ?>
        <?php if (!isset($_GET['action']) || $_GET['action'] !== 'login'): ?>
            <form method="post" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>">
                <label for="username">Uživatelské jméno:</label><br>
                <input type="text" id="username" name="username" required><br><br>
                <label for="email">Email:</label><br>
                <input type="email" id="email" name="email" required><br><br>
                <input type="submit" name="register" value="Registrovat se">
            </form>
            <p>Již máte účet? <a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>?action=login">Přihlásit se</a></p>
        <?php else: ?>
            <h2>Přihlášení</h2>
            <form method="post" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>">
                <label for="username">Uživatelské jméno:</label><br>
                <input type="text" id="username" name="username" required><br><br>
                <label for="password">Heslo (dočasné heslo z emailu):</label><br>
                <input type="password" id="password" name="password" required><br><br>
                <input type="submit" name="login" value="Přihlásit se">
            </form>
        <?php endif; ?>
    <?php else: ?>
        <p>Jste přihlášen jako <?php echo htmlspecialchars(auth_get_user()); ?>.</p>
        <p><a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>?logout=true">Odhlásit se</a></p>
    <?php endif; ?>
</body>
</html>
