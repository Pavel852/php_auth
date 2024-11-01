<?php
// Načtení knihovny auth.php
require_once 'auth.php';

// Inicializace session
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Simulovaná uživatelská data uložená v session (pro účely tohoto příkladu)
if (!isset($_SESSION['users'])) {
    $_SESSION['users'] = [
        'uzivatel1' => [
            'username' => 'uzivatel1',
            'password' => password_hash('tajneheslo', PASSWORD_DEFAULT),
            'userid' => 1,
            'email' => 'uzivatel1@example.com',
            'is_verified' => true,
        ],
    ];
}

// Inicializace zprávy
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
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
    header('Location: login_single.php');
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
    <h1>Přihlášení jménem a heslem</h1>
    <?php if (!empty($message)): ?>
        <p><?php echo htmlspecialchars($message); ?></p>
    <?php endif; ?>
    <?php if (!auth_is_logged_in()): ?>
        <form method="post" action="login_single.php">
            <label for="username">Uživatelské jméno:</label><br>
            <input type="text" id="username" name="username" required><br><br>
            <label for="password">Heslo:</label><br>
            <input type="password" id="password" name="password" required><br><br>
            <input type="submit" value="Přihlásit se">
        </form>
    <?php else: ?>
        <p>Jste přihlášen jako <?php echo htmlspecialchars(auth_get_user()); ?>.</p>
        <p><a href="login_single.php?logout=true">Odhlásit se</a></p>
    <?php endif; ?>
</body>
</html>
