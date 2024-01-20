<?php
    require_once "includes/session.php";
    require_once "includes/funcs.php";
    $conn = connect();
    // update file
    if(isset($_POST['id']) && isset($_POST['filename']) && isset($_POST['contents'])){
        rename_file($_POST['id'], $_POST['filename'], $_SESSION['user_id']);
        // todo - implement file contents update
    } else  if(isset($_POST['filename']) && isset($_POST['contents'])){
        create_file($_POST['filename'], $_POST['contents'], $_SESSION['user_id']); 
    }
    // display file
    if(isset($_GET['id'])){
        $display_file = get_file_by_id($_GET['id'], $_SESSION['user_id']);
        if($display_file){
            $file_contents = $display_file['file_contents'];
            $file_name = $display_file['file_name'];
        } else {
            # file doesn't exist
            exit(header("Location: /"));
        }
    } else {
        $file_contents = '';
        $file_name = '';
    }
    if(isset($_GET['id'])){
        $id = intval($_GET['id']);
    } else {
        $id = "";
    }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Virtual File Explorer</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f4f4f4;
        }

        h1 {
            color: #333;
        }

        .file-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .file-item {
            padding: 10px;
            border-bottom: 1px solid #ddd;
            display: flex;
            align-items: center;
        }

        .file-icon {
            width: 20px;
            height: 20px;
            margin-right: 10px;
        }

        .file-name {
            flex: 1;
        }

        .file-size {
            margin-left: 20px;
            color: #777;
        }
    </style>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-C6RzsynM9kWDrMNeT87bh95OGNyZPhcTNXj1NW7RuBCsyN/o0jlpcV8Qyq46cDfL" crossorigin="anonymous"></script>
</head>
<body>
    <br/>
    <div>
    <h1 style="text-align:center">Text Filesystem</h1>
    <hr>
    </div>
    <div class="container">
    <h1> Create a new text file</h1>
    <div class="mb-3">
    <form action="" method="POST">
    <?php if (isset($_GET['id'])){ echo '<input type="hidden" name="id" value="'.htmlspecialchars($_GET['id']).'">'; } ?>
    <label for="fileName" class="form-label">File Name</label>
    <input type="text" name="filename" class="form-control" id="fileName" placeholder="bighax.txt" value="<?php echo htmlspecialchars($file_name); ?>">
    </div>
    <div class="mb-3">
    <label for="contents" class="form-label">File Contents</label>
    <textarea name="contents" class="form-control" id="contents" rows="10"><?php echo htmlspecialchars($file_contents); ?></textarea>
    <br>
    <div class="text-center"><button type="submit" class="btn btn-primary"><?php if(isset($_GET['id'])){ echo 'Update'; } else { echo 'Submit'; } ?></button></div>
    </form>
    </div>
    </div>
    <hr>
    <div class="container">
        <h1> Your Files</h1>
        <?php
            $files = get_files($_SESSION['user_id']); 
            if (count($files) > 0) {
                echo <<<EOT
                <table class="table">
                <tr>
                    <th scope="col">File Name</th>
                    <th scope="col">File Size</th>
                    <th scope="col">Creation Date</th>
                    <th scope="col">Last Modified</th>
                    <th scope="col">File Owner</th>
                </tr>
                EOT;
                foreach ($files as $file){
                    echo "
                    <tr>
                        <td><a href='/?id={$file['id']}'>".htmlspecialchars($file['file_name'])."</a></td>
                        <td>".strlen($file['file_contents'])."</td>
                        <td>{$file['creation_date']}</td>
                        <td>{$file['last_modified']}</td>
                        <td>{$file['file_owner']}</td>
                    </tr>
                    ";
                }
                echo "</table>";
            } else {
                echo <<<EOT
                You do not have any files.
                EOT;
            }
        ?>
    </div>
</body>
</html>
