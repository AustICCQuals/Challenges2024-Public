<?php

function connect(){
    $conn = new mysqli("mariadb","root","supersecretpassword123!","data");
    return $conn;
}

function get_files($user_id){
    $conn = connect();
    $query = "SELECT * FROM files WHERE file_owner = ?";
    $prep = $conn->prepare($query);
    $prep->bind_param("s", $user_id);
    $prep->execute();
    $result = $prep->get_result();
    $files = Array();
    if($result !== false){
        for ($row_no = $result->num_rows - 1; $row_no >= 0; $row_no--) {
            $result->data_seek($row_no);
            $files[$row_no] = $result->fetch_assoc();
        }
        return $files;
    }
    return False;
}

function get_file_by_id($id, $user_id){
    $conn = connect();
    $query = "SELECT * FROM files WHERE id = ? AND file_owner = ? LIMIT 1";
    $prep = $conn->prepare($query);
    $prep->bind_param("is", $id, $user_id);
    $prep->execute();
    $result = $prep->get_result();
    if($result !== false){
        $result->data_seek(0);
        $file = $result->fetch_assoc();
        return $file;
    }
    return False;
}

function create_file($filename, $content, $user_id){
    $conn = connect();
    $query = "INSERT INTO files (file_name, file_owner, file_contents) VALUES (?, ?, ?)";
    $prep = $conn->prepare($query);
    $prep->bind_param("sss", $filename, $user_id, $content);
    $prep->execute();
    $result = $prep->get_result();
    exit(header("Location: /?id={$conn->insert_id}"));
    
}

function rename_file($file_id, $new_file_name, $file_owner){
    $conn = connect();
    # get the current file details
    $query = "SELECT * FROM files WHERE id = ? AND file_owner = ? LIMIT 1";
    # prepare the query
    $prep = $conn->prepare($query);
    $prep->bind_param("is", $file_id, $file_owner);
    $prep->execute();
    $result = $prep->get_result();
    if($result !== false){
        # get first row returned
        $result->data_seek(0);
        $file_data = $result->fetch_assoc();
        # recreate the file entry and remove the original entry
        $query = "INSERT INTO files (file_name, file_owner, file_contents) VALUES (?, ?, '{$file_data['file_contents']}')";
        $prep = $conn->prepare($query);
        $prep->bind_param("ss", $new_file_name, $file_owner);
        $prep->execute();
        $result = $prep->get_result();
        # get insert id
        $new_file_id = $conn->insert_id;
        # delete the original file entry
        $query = "DELETE FROM files WHERE id = ? AND file_owner = ?";
        $prep = $conn->prepare($query);
        $prep->bind_param("is", $file_id, $file_owner);
        $prep->execute();
        # redirect to the new file
        exit(header("Location: /?id={$new_file_id}"));
    }
}

?>