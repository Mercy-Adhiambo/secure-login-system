/secure-login
│
├── index.html         # Login form
├── register.html      # Registration form
├── dashboard.php      # Protected page after login
├── login.php          # Login logic
├── register.php       # Registration logic
├── logout.php         # Logout logic
├── db.php             # Database connection
├── .gitignore
└── README.md


1.DEVELOP A SECURE LOGIN SYSTEM USING HTML ,Javascript and PHP/ASP.NET
login.html (Frontend)
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login System</title>
    <script src="login.js"></script>
</head>
<body>
    <h2>Login</h2>
    <form action="login.php" method="POST" onsubmit="return validateForm()">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username" required><br><br>
        
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password" required><br><br>

        <input type="submit" value="Login">
    </form>
</body>
</html>

B)login.js (Frontend JavaScript)
function validateForm() {
    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;

    if (username === "" || password === "") {
        alert("Both fields are required!");
        return false; // Prevent form submission if validation fails
    }
    return true; // Allow form submission
}

C)login.php (Backend PHP)
<?php
session_start();
include('config.php'); // Include your database connection file

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Hardcoding the username "Mercy Adhiambo" for testing
    if ($username === "Mercy Adhiambo") {
        // Prepare the SQL query to check the password (replace 'users' with your actual table name)
        $stmt = $conn->prepare('SELECT id, password FROM users WHERE username = ?');
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $stmt->store_result();
        $stmt->bind_result($id, $hashed_password);

        if ($stmt->fetch()) {
            // Verify the password using password_hash() and password_verify()
            if (password_verify($password, $hashed_password)) {
                // Successful login, set session variables
                $_SESSION['user_id'] = $id;
                $_SESSION['username'] = $username;
                // Redirect to the dashboard or another protected page
                header("Location: dashboard.php");
                exit();
            } else {
                echo "Invalid credentials!"; // Invalid password
            }
        } else {
            echo "User not found!"; // Username not found in database
        }
        $stmt->close();
    } else {
        echo "Invalid username!";
    }
}
?>

D)config.php (Database Connection)
<?php
$servername = "localhost";  // Change to your database server
$username = "root";         // Your database username
$password = "";             // Your database password
$dbname = "secure_login_system"; // Your database name

// Create a connection to the database
$conn = new mysqli($servername, $username, $password, $dbname);

// Check if the connection is successful
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>

Database Setup
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL

);
$password = password_hash('your_password', PASSWORD_BCRYPT);
echo $password;

INSERT INTO users (username, password) VALUES ('Mercy Adhiambo', 'hashed_password_here');

B)IMPLEMENTING SESSION-BASED AUTHENTICATION
<?php
session_start(); // Start the session

include('config.php'); // Include database connection file

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Prepare SQL query to check if the user exists
    $stmt = $conn->prepare('SELECT id, password FROM users WHERE username = ?');
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($id, $hashed_password);

    if ($stmt->fetch()) {
        // If the password is correct, start the session and store user data in session
        if (password_verify($password, $hashed_password)) {
            $_SESSION['user_id'] = $id; // Store the user ID in the session
            $_SESSION['username'] = $username; // Store the username in the session

            // Redirect to the dashboard
            header("Location: dashboard.php");
            exit();
        } else {
            echo "Invalid credentials!";
        }
    } else {
        echo "User not found!";
    }
    $stmt->close();
}
?>
 CONFIGURING SESSION TIMEOUT IN
<?php
$servername = "localhost";
$username = "root"; // Database username
$password = ""; // Database password
$dbname = "secure_login_system"; // Database name

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>

PROTECTING OTHER PAGES WITH SESSIONS
<?php
session_start(); // Start the session

// Check if the user is logged in (if not, redirect them to the login page)
if (!isset($_SESSION['user_id'])) {
    header('Location: login.html'); // Redirect to login page if the user is not logged in
    exit();
}

// Display user dashboard (example: welcome message)
echo "<h2>Welcome, " . $_SESSION['username'] . "!</h2>";
?>

ADDING A LOGOUT FEATURE 
<?php
session_start(); // Start the session

// Destroy the session
session_unset();
session_destroy();

// Redirect to the login page after logout
header('Location: login.html');
exit();
?>


C)YSE PASSWORD HASHING AND SECURE COOKIES FOR AUTHENTICATION
<?php
session_start();
include('config.php');

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Prepare the SQL query to check if the user exists
    $stmt = $conn->prepare('SELECT id, password FROM users WHERE username = ?');
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($id, $hashed_password);

    if ($stmt->fetch()) {
        // If the password matches the hash, start the session
        if (password_verify($password, $hashed_password)) {
            $_SESSION['user_id'] = $id;  // Store user ID in session
            $_SESSION['username'] = $username;  // Store username in session

            // Set a secure, HttpOnly cookie for session tracking
            setcookie('user_id', $id, time() + (86400 * 30), "/", "", true, true);  // Secure, HttpOnly cookie

            // Redirect to the dashboard
            header("Location: dashboard.php");
            exit();
        } else {
            echo "Invalid credentials!";
        }
    } else {
        echo "User not found!";
    }
    $stmt->close();
}
?>

<form method="post">
    <label for="username">Username:</label><br>
    <input type="text" id="username" name="username" required><br><br>
    
    <label for="password">Password:</label><br>
    <input type="password" id="password" name="password" required><br><br>
    
    <input type="submit" value="Login">
</form>
 D)INCLUDE A FEATURE TO PREVENT SQL INJECTION ATTACKS
<?php
// Start session
session_start();

// Database connection
$servername = "localhost";
$dbUsername = "root";
$dbPassword = "";
$dbName = "secure_login_system";

// Create connection
$conn = new mysqli($servername, $dbUsername, $dbPassword, $dbName);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Handle registration
if (isset($_POST['register'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Hash password
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);

    // Prevent SQL injection using prepared statement
    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->bind_param("ss", $username, $hashed_password);

    if ($stmt->execute()) {
        echo "Registration successful!";
    } else {
        echo "Registration failed!";
    }

    $stmt->close();
}

// Handle login
if (isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Prevent SQL injection using prepared statement
    $stmt = $conn->prepare("SELECT id, password FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($id, $hashed_password);

    if ($stmt->fetch()) {
        if (password_verify($password, $hashed_password)) {
            // Correct password
            $_SESSION['user_id'] = $id;
            $_SESSION['username'] = $username;

            // Set secure cookie
            setcookie('user_id', $id, time() + (86400 * 30), "/", "", true, true);

            echo "Login successful! <a href='dashboard.php'>Go to Dashboard</a>";
        } else {
            echo "Invalid credentials!";
        }
    } else {
        echo "User not found!";
    }

    $stmt->close();
}
?>

<!-- Simple HTML Form -->
<h2>Register</h2>
<form method="post">
    <input type="text" name="username" placeholder="Username" required><br><br>
    <input type="password" name="password" placeholder="Password" required><br><br>
    <button type="submit" name="register">Register</button>
</form>

<br><hr><br>

<h2>Login</h2>
<form method="post">
    <input type="text" name="username" placeholder="Username" required><br><br>
    <input type="password" name="password" placeholder="Password" required><br><br>
    <button type="submit" name="login">Login</button>
</form>

git init
git add .
 git commit -m "Initial commit: Secure login system by Mercy Adhiambo"

git remote add origin https://github.com/MercyAdhiambo/secure-login-system.git
git push -u origin main












