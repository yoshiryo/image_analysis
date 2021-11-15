DROP DATABASE IF EXISTS analysys;
CREATE DATABASE analysys;

DROP TABLE IF EXISTS analysys.image;

CREATE TABLE analysys.image
(
    id              INTEGER             NOT NULL PRIMARY KEY,
    cve_id          VARCHAR(100)        NOT NULL,
    name            VARCHAR(64)         NOT NULL,
    version         VARCHAR(20)                 ,
    cve_score       VARCHAR(50)                 ,
    priority        VARCHAR(30)                 ,
    os_version      VARCHAR(200)                ,
    status          VARCHAR(200)                       
);
