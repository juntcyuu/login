<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

echo "Welcome to the system!";

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
</head>
<body>
    <h2>Welcome!</h2>
    <p>You have successfully logged in.</p>
    <form action="logout.php" method="POST">
        <button type="submit">Logout</button>
    </form>
</body>
</html>
