<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = $_POST['password'];

    // 数据库连接
    $conn = new mysqli('localhost', 'root', '', 'user_system');
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // 检查邮箱是否已注册
    $checkStmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $checkStmt->bind_param("s", $email);
    $checkStmt->execute();
    $checkStmt->store_result(); // 确保查询结果被存储

    if ($checkStmt->num_rows > 0) {
        // 如果邮箱已存在，直接显示错误信息并停留在当前页面
        $error_message = "Email is already registered. Please use a different email or login.";
        $checkStmt->close();
        $conn->close();
    } else {
        // 邮箱不存在，插入用户数据
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $insertStmt = $conn->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
        $insertStmt->bind_param("ss", $email, $hashedPassword);
        $insertStmt->execute();
        $insertStmt->close();
        $conn->close();
        header("Location: login.php"); // 注册成功后跳转到登录页面
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
</head>
<body>
    <h2>Register</h2>
    <?php if (isset($error_message)): ?>
        <div style="color: red;"><?php echo $error_message; ?></div>
    <?php endif; ?>
    <form action="register.php" method="POST">
        <label for="email">Email:</label>
        <input type="email" name="email" id="email" required>
        <br>
        <label for="password">Password:</label>
        <input type="password" name="password" id="password" required>
        <br>
        <button type="submit">Register</button>
    </form>
    <p>Already have an account? <a href="login.php">Login here</a></p>
</body>
</html>
