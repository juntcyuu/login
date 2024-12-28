<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];

    // 数据库连接
    $conn = new mysqli('localhost', 'root', '', 'user_system');
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    $stmt = $conn->prepare("SELECT id, password, failed_attempts, is_verified FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result(); // 确保查询结果被存储

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($userId, $hashedPassword, $failedAttempts, $isVerified);
        $stmt->fetch(); // 获取结果

        if (password_verify($password, $hashedPassword)) {
            if ($failedAttempts >= 3) {
                echo "Account locked. Please check your email.";
            } else {
                if ($isVerified == 0) {
                    $_SESSION['temp_user_id'] = $userId; // 临时保存用户ID
                    // 生成并发送 OTP
                    $otp = rand(100000, 999999);
                    $updateOtpStmt = $conn->prepare("UPDATE users SET otp_code = ? WHERE id = ?");
                    $updateOtpStmt->bind_param("si", $otp, $userId);
                    $updateOtpStmt->execute();

                    // 确保 `UPDATE` 查询执行完后关闭结果集
                    $updateOtpStmt->close();

                    // 发送 OTP 到用户邮箱
                    $subject = "Verify Your Email";
                    $message = "Your OTP code is: $otp";
                    $headers = "From: noreply@example.com";
                    if (mail($email, $subject, $message, $headers)) {
                        echo "OTP sent to your email. Please verify to complete login.";
                        header("Location: verify_login.php"); // 跳转到 OTP 验证页面
                        exit;
                    } else {
                        echo "Failed to send OTP. Please try again later.";
                    }
                } else {
                    // 用户已验证，重置失败尝试计数
                    $resetStmt = $conn->prepare("UPDATE users SET failed_attempts = 0 WHERE id = ?");
                    $resetStmt->bind_param("i", $userId);
                    $resetStmt->execute();
                    $resetStmt->close();

                    $_SESSION['user_id'] = $userId; // 保存会话
                    header("Location: welcome.php"); // 跳转到欢迎页面
                    exit;
                }
            }
        } else {
            // 如果密码错误，更新失败次数
            $failedAttempts++;
            $updateStmt = $conn->prepare("UPDATE users SET failed_attempts = ? WHERE id = ?");
            $updateStmt->bind_param("ii", $failedAttempts, $userId);
            $updateStmt->execute();
            $updateStmt->close();

            if ($failedAttempts >= 3) {
                $subject = "Account Locked";
                $message = "Your account has been locked due to multiple failed login attempts.";
                $headers = "From: noreply@example.com";
                mail($email, $subject, $message, $headers);
            }

            echo "Invalid email or password.";
        }
    } else {
        echo "No account found with this email.";
    }

    // 关闭查询
    $stmt->free_result();
    $stmt->close();
    $conn->close();
}
?>



<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    <form action="login.php" method="POST">
        <label for="email">Email:</label>
        <input type="email" name="email" id="email" required>
        <br>
        <label for="password">Password:</label>
        <input type="password" name="password" id="password" required>
        <br>
        <button type="submit">Login</button>
    </form>
    <p>Don't have an account? <a href="register.php">Register here</a>.</p>
</body>
</html>
