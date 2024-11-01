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
        'uzivatel4' => [
            'username' => 'uzivatel4',
            'password' => password_hash('puvodniheslo', PASSWORD_DEFAULT),
            'userid' => 4,
            'email' => 'uzivatel4@example.com',
            'is_verified' => true,
        ],
    ];
}

// Inicializace zprávy
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    // Uživatelský vstup pro přihlášení
    $input_username = $_POST['username'] ?? '';
    $input_password = $_POST['password'] ?? '';

    if (empty($input_username) || empty($input_password)) {
        $message = 'Prosím vyplňte obě pole.';
    } else {
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

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reset_request'])) {
    // Žádost o reset hesla
    $email = $_POST['email'] ?? '';
    if (empty($email)) {
        $message = 'Prosím zadejte svůj email.';
    } else {
        $found = false;
        foreach ($_SESSION['users'] as &$user_data) {
            if ($user_data['email'] === $email) {
                $found = true;
                $reset_request = auth_request_password_reset($email, $user_data);
                if (is_array($reset_request)) {
                    // Odeslání emailu s resetovacím odkazem
                    $reset_link = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'] . '?action=reset&token=' . $reset_request['reset_token'] . '&username=' . urlencode($user_data['username']);
                    $subject = 'Reset hesla';
                    $message_email = "Klikněte na následující odkaz pro resetování hesla:\n$reset_link";
                    // mail($email, $subject, $message_email); // Odkomentujte pro odeslání emailu

                    $message = "Instrukce pro reset hesla byly odeslány na váš email.\n\n$reset_link"; // Pro testování zobrazíme odkaz
                } else {
                    $message = "Chyba při žádosti o reset hesla: " . $reset_request;
                }
                break;
            }
        }
        if (!$found) {
            $message = 'Email nebyl nalezen.';
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['reset_password'])) {
    if (isset($_GET['token']) && isset($_GET['username'])) {
        $token = $_GET['token'];
        $username = $_GET['username'];

        // Načtení uživatelských dat
        if (isset($_SESSION['users'][$username])) {
            $user_data = &$_SESSION['users'][$username];
            $new_password = $_POST['new_password'] ?? '';
            $confirm_password = $_POST['confirm_password'] ?? '';

            if (empty($new_password) || empty($confirm_password)) {
                $message = 'Prosím vyplňte obě pole.';
            } elseif ($new_password !== $confirm_password) {
                $message = 'Hesla se neshodují.';
            } else {
                $reset_result = auth_reset_password($token, $new_password, $user_data);

                if ($reset_result === true) {
                    $message = "Heslo bylo úspěšně resetováno.";
                    // Přesměrování na přihlašovací část
                    header('Location: ' . $_SERVER['PHP_SELF']);
                    exit();
                } else {
                    $message = "Chyba při resetování hesla: " . $reset_result;
                }
            }
        } else {
            $message = "Uživatel nenalezen.";
        }
    } else {
        $message = "Neplatný odkaz.";
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
    <title>Přihlášení s resetem hesla</title>
</head>
<body>
    <h1>Přihlášení jménem a heslem</h1>
    <?php if (!empty($message)): ?>
        <p><?php echo nl2br(htmlspecialchars($message)); ?></p>
    <?php endif; ?>
    <?php if (!auth_is_logged_in()): ?>
        <?php if (!isset($_GET['action']) || $_GET['action'] !== 'reset'): ?>
            <form method="post" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>">
                <label for="username">Uživatelské jméno:</label><br>
                <input type="text" id="username" name="username" required><br><br>
                <label for="password">Heslo:</label><br>
                <input type="password" id="password" name="password" required><br><br>
                <input type="submit" name="login" value="Přihlásit se">
            </form>
            <h2>Zapomněli jste heslo?</h2>
            <form method="post" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>">
                <label for="email">Zadejte svůj email:</label><br>
                <input type="email" id="email" name="email" required><br><br>
                <input type="submit" name="reset_request" value="Resetovat heslo">
            </form>
        <?php else: ?>
            <h2>Reset hesla</h2>
            <form method="post" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF'] . '?action=reset&token=' . urlencode($_GET['token']) . '&username=' . urlencode($_GET['username'])); ?>">
                <label for="new_password">Nové heslo:</label><br>
                <input type="password" id="new_password" name="new_password" required><br><br>
                <label for="confirm_password">Potvrďte nové heslo:</label><br>
                <input type="password" id="confirm_password" name="confirm_password" required><br><br>
                <input type="submit" name="reset_password" value="Resetovat heslo">
            </form>
        <?php endif; ?>
    <?php else: ?>
        <p>Jste přihlášen jako <?php echo htmlspecialchars(auth_get_user()); ?>.</p>
        <p><a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>?logout=true">Odhlásit se</a></p>
    <?php endif; ?>
</body>
</html>
