FROM mariadb:10.6

COPY ./config/sql/schema.sql /docker-entrypoint-initdb.d/schema.sql