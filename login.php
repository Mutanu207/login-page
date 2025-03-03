<?php
session_start();

// Database connection details – replace these with your actual credentials
$host = 'localhost';
$db   = 'your_database_name';
$user = 'your_database_username';
$pass = 'your_database_password';
$charset = 'utf8mb4';

// DSN (Data Source Name)
$dsn = "mysql:host=$host;dbname=$db;charset=$charset";

// PDO options
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
    // For production, you might log this instead of displaying it
    die("Database connection failed: " . $e->getMessage());
}

// Check if the form was submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Retrieve and sanitize the form inputs
    $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];

    // Prepare SQL statement to prevent SQL injection
    $stmt = $pdo->prepare("SELECT id, email, password_hash FROM users WHERE email = :email");
    $stmt->execute(['email' => $email]);
    $userData = $stmt->fetch();

    if ($userData) {
        // Verify the password using password_verify()
        if (password_verify($password, $userData['password_hash'])) {
            // Correct password: start a session and store user data
            $_SESSION['user_id'] = $userData['id'];
            $_SESSION['email'] = $userData['email'];
            // Redirect to a secure dashboard page
            header('Location: dashboard.php');
            exit();
        } else {
            // Password does not match
            echo "Incorrect password!";
        }
    } else {
        // User not found
        echo "User not found!";
    }
}
?>
