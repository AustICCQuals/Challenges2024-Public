<?php
    session_start();
    if (!isset($_SESSION['user_id'])){
        # generate random string as username
        $_SESSION['user_id'] = bin2hex(random_bytes(5));
    }
?>