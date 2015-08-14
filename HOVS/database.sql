CREATE DATABASE HOVS;

CREATE TABLE admin (
email varchar(255),
fname varchar(100),
sname varchar(100),
password varchar(255)
);


CREATE TABLE scans (
scanid INT AUTO INCREMENT NOT_NULL,
name varchar(255),
email varchar(255),
phone varchar(255),
company varchar(255),
number varchar(255),
target varchar(255),
PRIMARY KEY (scanid)
);
