
# PHP Authentication Library

## Overview

`auth.php` is a simple PHP authentication library that provides essential user authentication functionalities without relying on an internal database. It uses arrays to manage user data and MD5 for password hashing. The library includes features such as user registration, login, logout, password reset, and email verification.

## Functions

### `auth_settings($params = "")`

Sets the configuration parameters for the authentication library.

- **Parameters**: 
  - `$params` (string): Configuration parameters in the format `"key=value, key=value, ..."`.
- **Usage**:
  ```php
  auth_settings("email_verification=true, numeric_password_length=6, reset_token_expiry=3600, verification_token_expiry=86400, passwd_verification=true");
  ```

### `auth_version()`

Returns the current version of the authentication system.

- **Returns**: 
  - (string) The version number.
- **Usage**:
  ```php
  print auth_version(); // Output: 1.0
  ```

### `generateNumericPassword($length = 6)`

Generates a random numeric password.

- **Parameters**:
  - `$length` (int): The number of digits in the password.
- **Returns**:
  - (string) The generated numeric password.
- **Usage**:
  ```php
  $password = generateNumericPassword(6); // e.g., "482915"
  ```

### `generateToken()`

Generates a random token.

- **Returns**:
  - (string) A 32-character hexadecimal token.
- **Usage**:
  ```php
  $token = generateToken(); // e.g., "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
  ```

### `auth_register($username, $password = null, $userid = null, $email = null)`

Registers a new user.

- **Parameters**:
  - `$username` (string|array): Username or an array of user data.
  - `$password` (string|null): Password (optional if email verification is enabled).
  - `$userid` (mixed): User ID (optional).
  - `$email` (string|null): Email address (optional).
- **Returns**:
  - (array|bool|string) User data array on success or `true` if no email verification is required, otherwise an error message.
- **Usage**:
  ```php
  $user = auth_register('john_doe', 'securepassword', 1001, 'john@example.com');
  ```

### `auth_login($identifier, $password, $user_data)`

Logs in a user.

- **Parameters**:
  - `$identifier` (string|int): Username or User ID.
  - `$password` (string): Password.
  - `$user_data` (array): User data array.
- **Returns**:
  - (bool|string) `true` on success, otherwise an error message.
- **Usage**:
  ```php
  $result = auth_login('john_doe', 'securepassword', $user_data);
  if ($result === true) {
      echo "Login successful!";
  } else {
      echo "Login failed: " . $result;
  }
  ```

### `auth_logout()`

Logs out the current user.

- **Returns**:
  - (void)
- **Usage**:
  ```php
  auth_logout();
  echo "You have been logged out.";
  ```

### `auth_request_password_reset($email, $user_data)`

Requests a password reset.

- **Parameters**:
  - `$email` (string): User's email address.
  - `$user_data` (array): User data array.
- **Returns**:
  - (array|bool|string) Array with reset token and expiry on success, otherwise an error message.
- **Usage**:
  ```php
  $reset = auth_request_password_reset('john@example.com', $user_data);
  if (is_array($reset)) {
      echo "Reset token: " . $reset['reset_token'];
  } else {
      echo "Error: " . $reset;
  }
  ```

### `auth_reset_password($token, $new_password, &$user_data)`

Resets the user's password using a reset token.

- **Parameters**:
  - `$token` (string): Reset token.
  - `$new_password` (string): New password.
  - `&$user_data` (array): Reference to user data array.
- **Returns**:
  - (bool|string) `true` on success, otherwise an error message.
- **Usage**:
  ```php
  $result = auth_reset_password('reset_token_here', 'newpassword', $user_data);
  if ($result === true) {
      echo "Password reset successful!";
  } else {
      echo "Error: " . $result;
  }
  ```

### `auth_verify_email($token, &$user_data)`

Verifies the user's email using a verification token.

- **Parameters**:
  - `$token` (string): Verification token.
  - `&$user_data` (array): Reference to user data array.
- **Returns**:
  - (array|bool|string) `true` on success or array with additional data if password verification is required, otherwise an error message.
- **Usage**:
  ```php
  $result = auth_verify_email('verification_token_here', $user_data);
  if ($result === true) {
      echo "Email verified successfully!";
  } elseif (is_array($result)) {
      echo "Set password using token: " . $result['set_password_token'];
  } else {
      echo "Error: " . $result;
  }
  ```

### `auth_get_user()`

Gets the currently logged-in user.

- **Returns**:
  - (string|null) Username or `null` if not logged in.
- **Usage**:
  ```php
  $user = auth_get_user();
  echo "Logged in as: " . $user;
  ```

### `auth_is_logged_in()`

Checks if a user is currently logged in.

- **Returns**:
  - (bool) `true` if logged in, otherwise `false`.
- **Usage**:
  ```php
  if (auth_is_logged_in()) {
      echo "User is logged in.";
  } else {
      echo "User is not logged in.";
  }
  ```

## Examples

### 1. Registration and Login with Username and Password

#### Registration

```php
<?php
require_once 'auth/init.php';
auth_settings("email_verification=false, passwd_verification=false");

$user = auth_register('john_doe', 'securepassword', 1001, 'john@example.com');
if ($user === true) {
    echo "Registration successful!";
} else {
    echo "Registration failed: " . $user;
}
?>
```
