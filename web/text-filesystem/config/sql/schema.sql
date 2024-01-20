CREATE DATABASE data;
USE data;
CREATE TABLE files (
    id int NOT NULL AUTO_INCREMENT,
    file_name varchar(255),
    file_owner varchar(255),
    file_contents varchar(255),
    creation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

CREATE TABLE flag (
    flag varchar(255)
);

INSERT INTO flag VALUES ("oiccflag{62d070b52c79178ff240c3d2edbf71d4}");
