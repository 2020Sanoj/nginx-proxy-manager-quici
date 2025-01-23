<?php
require_once __DIR__ . "/../../../functions/database.php";
$db = db();
if ($db->querySingle("SELECT COUNT(*) FROM auth") === 0) {
    session_destroy();
    header("Location: /auth/setup", true, 307);
    exit();
}

require_once __DIR__ . "/../../../functions/auth.php";
if (isAuthenticated()) {
    header("Location: /", true, 307);
    exit();
} else {

    require_once __DIR__ . "/../../../functions/email.php";
    require_once __DIR__ . "/../../../functions/totp.php";
    session_unset();
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>NPMplus - Login</title>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="application-name" content="NPMplus" />
    <meta name="author" content="ZoeyVid" />
    <meta name="description" content="Login Page for NPMplus" />
    <meta name="keywords" content="NPMplus, login" />
    <link rel="stylesheet" href="/tailwind.css" />
    <link rel="icon" type="image/webp" href="/favicon.webp" />
    <!--<script src="https://js.hcaptcha.com/1/api.js?hl=en&render=onload&recaptchacompat=off" async defer></script>-->
</head>

<body class="text-center font-sans bg-white text-black dark:bg-slate-900 dark:text-white">
<div class="rounded-3xl absolute p-4 md:px-20 px-8 w-max top-2/4 left-2/4 -translate-y-2/4 -translate-x-2/4 bg-slate-200 dark:bg-slate-800">
    <?php
    function login($msg): void
    {
        ?>
    <h1 class="text-3xl md:text-6xl font-bold mt-3 mb-6 mx-0">NPMplus - Login</h1>
    <form method="post" class="grid grid-cols-1 gap-y-4 md:grid-cols-4 md:grid-rows-4">
        <label for="email" class="mr-2 text-left md:text-right">E-Mail:</label>
        <input type="email" name="email" id="email" maxlength="255" placeholder="E-Mail" class="h-8 rounded-lg bg-transparent border border-zinc-600 dark:border-zinc-300 outline-hidden focus:ring-1 ring-offset-1 transition-shadow shadow-black dark:shadow-white ring-zinc-500 dark:ring-zinc-200 py-2 px-3 md:col-span-2" required>
        <span class="hidden md:block"></span>
        <label for="pswd" class="mr-2 text-left md:text-right">Password:</label>
        <input type="password" name="pswd" id="pswd" maxlength="255" placeholder="Password" class="h-8 rounded-lg bg-transparent border border-zinc-600 dark:border-zinc-300 outline-hidden focus:ring-1 ring-offset-1 transition-shadow shadow-black dark:shadow-white ring-zinc-500 dark:ring-zinc-200 py-2 px-3 md:col-span-2" required>
        <span class="hidden md:block"></span>
        <label for="totp" class="mr-2 text-left md:text-right">TOTP:</label>
        <input type="text" name="totp" id="totp" maxlength="6" placeholder="TOTP" class="h-8 rounded-lg bg-transparent border border-zinc-600 dark:border-zinc-300 outline-hidden focus:ring-1 ring-offset-1 transition-shadow shadow-black dark:shadow-white ring-zinc-500 dark:ring-zinc-200 py-2 px-3 md:col-span-2">
        <span class="hidden md:block"></span>
        <!--<div class="h-captcha" data-sitekey="<?php //echo $hcaptcha_key;
        ?>"></div>--> 
        <input type="submit" value="Login" onClick="this.disabled=true;" class="bg-[#296236] hover:bg-[#23552f] text-white font-bold text-xl p-2 px-4 w-full space-y-4 rounded-full disabled:cursor-not-allowed disabled:opacity-75 shadow-md transition-transform transform active:scale-95 col-span-1 md:col-span-4">
    </form>
        <?php
        $msg = match ($msg) {
            "adne" => "Account does not exist.",
            "wpw" => "Wrong password.",
            "mtotp" => "Missing TOTP.",
            "wtotp" => "Wrong TOTP.",
            default => "Please login.",
        };
        echo "<p class='font-bold mt-2'>Note: " . $msg . "</p>";
    }
    if (!array_key_exists("email", $_POST) || !array_key_exists("pswd", $_POST)) {
        login("none");
    } else {
        $_SESSION["LOGIN_TIME"] = time();
        $query = $db->prepare("SELECT * FROM auth WHERE email=:email");
        $query->bindValue(":email", $_POST["email"]);
        $queryresult = $query->execute()->fetchArray();

        if (is_array($queryresult) && validateEmail($_POST["email"])) {
            if (!password_verify($_POST["pswd"], $queryresult["pswd"])) {
                sendMail($_POST["email"], "Failed Login", $_SERVER["REMOTE_ADDR"] . " failed to login into your account.");
                login("wpw");
            } else {
                if (empty($queryresult["totp"])) {
                    sendMail($_POST["email"], "New Login", $_SERVER["REMOTE_ADDR"] . " logged into your account");
                    $_SESSION["AUTH_PW_HASH"] = hash("sha256", $queryresult["pswd"]);
                    header("Location: /", true, 307);
                    exit();
                } else {
                    if (empty($_POST["totp"])) {
                        sendMail($_POST["email"], "Failed Login", $_SERVER["REMOTE_ADDR"] . " failed to login into your account.");
                        login("mtotp");
                    } else {
                        if ($_POST["totp"] === totp($queryresult["totp"])) {
                            sendMail($_POST["email"], "New Login", $_SERVER["REMOTE_ADDR"] . " logged into your account");
                            $_SESSION["AUTH_EMAIL"] = $_POST["email"];
                            $_SESSION["AUTH_PW_HASH"] = hash("sha256", $queryresult["pswd"]);
                            $_SESSION["AUTH_TOTP_HASH"] = hash("sha256", $queryresult["totp"]);
                            header("Location: /", true, 307);
                            exit();
                        } else {
                            sendMail($_POST["email"], "Failed Login", $_SERVER["REMOTE_ADDR"] . " failed to login into your account.");
                            login("wtotp");
                        }
                    }
                }
            }
        } else {
            login("adne");
        }
    }
    ?>
</div>
</body>
</html>
<?php
} ?>
