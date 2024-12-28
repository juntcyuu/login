<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $otp = $_POST['otp'];

    $conn = new mysqli('localhost', 'root', '', 'user_system');
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    $stmt = $conn->prepare("SELECT otp_code FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->bind_result($dbOtp);
    $stmt->fetch();

    if ($dbOtp === $otp) {
        $updateStmt = $conn->prepare("UPDATE users SET is_verified = 1 WHERE email = ?");
        $updateStmt->bind_param("s", $email);
        $updateStmt->execute();
        echo "Email verified successfully!";
    } else {
        echo "Invalid OTP.";
    }

    $stmt->close();
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify OTP</title>
</head>
<body>
    <h2>Verify OTP</h2>
    <form action="verify.php" method="POST">
        <label for="email">Email:</label>
        <input type="email" name="email" id="email" required>
        <br>
        <label for="otp">OTP:</label>
        <input type="text" name="otp" id="otp" required>
        <br>
        <button type="submit">Verify</button>
    </form>
</body>
</html>
