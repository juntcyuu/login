<?php
session_start();

if (!isset($_SESSION['temp_user_id'])) {
    header("Location: login.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $otp = $_POST['otp'];

    // 数据库连接
    $conn = new mysqli('localhost', 'root', '', 'user_system');
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    $userId = $_SESSION['temp_user_id'];
    $stmt = $conn->prepare("SELECT otp_code FROM users WHERE id = ?");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $stmt->store_result(); // 确保查询结果被存储

    if ($stmt->num_rows > 0) {
        $stmt->bind_result($dbOtp);
        $stmt->fetch(); // 获取结果

        if ($otp === $dbOtp) {
            // 验证成功，更新用户状态为已验证
            $updateStmt = $conn->prepare("UPDATE users SET is_verified = 1 WHERE id = ?");
            $updateStmt->bind_param("i", $userId);
            $updateStmt->execute();
            $updateStmt->close();

            // 用户认证通过，移除临时存储的用户ID
            $_SESSION['user_id'] = $userId; // 认证通过后设置正式会话
            unset($_SESSION['temp_user_id']); // 移除临时用户ID
            header("Location: welcome.php"); // 跳转到欢迎页面
            exit;
        } else {
            echo "Invalid OTP.";
        }
    } else {
        echo "No OTP found for this user.";
    }

    // 释放结果集并关闭查询
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
    <title>Verify Login</title>
</head>
<body>
    <h2>Verify Your OTP</h2>
    <form action="verify_login.php" method="POST">
        <label for="otp">Enter OTP:</label>
        <input type="text" name="otp" id="otp" required>
        <br>
        <button type="submit">Verify</button>
    </form>
</body>
</html>
