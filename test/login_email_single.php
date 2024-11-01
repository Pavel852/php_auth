<?php
// Načtení knihovny auth.php
require_once 'auth.php';

// Inicializace session
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Simulovaná uživatelská data uložená v session
if (!isset($_SESSION['users'])) {
    $_SESSION['users'] = [
        'uzivatel2' => [
            'username' => 'uzivatel2',
            'password' => password_hash('druheheslo', PASSWORD_DEFAULT),
            'userid' => 2,
            'email' => 'uzivatel2@example.com',
            'is_verified' => true,
        ],
    ];
}

// Inicializace zprávy
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Uživatelský vstup
    $input_username = $_POST['username'] ?? '';
    $input_email = $_POST['email'] ?? '';

    // Validace vstupu
    if (empty($input_username) || empty($input_email)) {
        $message = 'Prosím vyplňte obě pole.';
    } else {
        // Pokus o přihlášení
        if (isset($_SESSION['users'][$input_username])) {
            $user_data = $_SESSION['users'][$input_username];
            if ($user_data['email'] === $input_email) {
                // Nastavení session
                $_SESSION['user_id'] = $user_data['userid'];
                $_SESSION['username'] = $user_data['username'];
                $message = "Přihlášení bylo úspěšné. Vítejte, " . htmlspecialchars(auth_get_user()) . "!";
            } else {
                $message = 'Nesprávný email.';
            }
        } else {
            $message = 'Uživatel neexistuje.';
        }
    }
}

if (isset($_GET['logout'])) {
    auth_logout();
    header('Location: login_email_single.php');
    exit();
}
?>
<!DOCTYPE html>
<html lang="cs">
<head>
    <meta charset="UTF-8">
    <title>Přihlášení</title>
</head>
<body>
    <h1>Přihlášení jménem a emailem</h1>
    <?php if (!empty($message)): ?>
        <p><?php echo htmlspecialchars($message); ?></p>
    <?php endif; ?>
    <?php if (!auth_is_logged_in()): ?>
        <form method="post" action="login_email_single.php">
            <label for="username">Uživatelské jméno:</label><br>
            <input type="text" id="username" name="username" required><br><br>
            <label for="email">Email:</label><br>
            <input type="email" id="email" name="email" required><br><br>
            <input type="submit" value="Přihlásit se">
        </form>
    <?php else: ?>
        <p>Jste přihlášen jako <?php echo htmlspecialchars(auth_get_user()); ?>.</p>
        <p><a href="login_email_single.php?logout=true">Odhlásit se</a></p>
    <?php endif; ?>
</body>
</html>
