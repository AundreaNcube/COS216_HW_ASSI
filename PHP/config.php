<?php

/*
Amantle Keamogetse Temo u23539764 
Aundrea Ncube u22747363
*/
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_lifetime' => 86400,
        'read_and_close'  => false, 
        'use_strict_mode' => true
    ]);
}

class ConnectToDatabase
{
    private static $instance = null;
    private $host = "wheatley.cs.up.ac.za";
    private $username = "u23539764";
    private $password = "FPDTAWKZVCK66U2XVBVSITRCK272WHJQ";
    private $dbname = "u23539764_u22747363_HA";
    private $connection;

    private function __construct()
    {
        $this->connection = new mysqli(
            $this->host,
            $this->username,
            $this->password,
            $this->dbname
        );

        if ($this->connection->connect_errno) {
            throw new RuntimeException(
                "Connection failed: [" . $this->connection->connect_errno . "] " .
                    $this->connection->connect_error
            );
        }

        $this->connection->set_charset("utf8mb4");
    }

    public static function getInstance()
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function getConnection()
    {
        if (!$this->connection || !$this->connection->ping()) {
            $this->connection = new mysqli(
                $this->host,
                $this->username,
                $this->password,
                $this->dbname
            );

            if ($this->connection->connect_errno) {
                throw new RuntimeException(
                    "Reconnection failed: [" . $this->connection->connect_errno . "] " .
                        $this->connection->connect_error
                );
            }

            $this->connection->set_charset("utf8mb4");
        }
        return $this->connection;
    }

    private function __clone() {}

    public function __wakeup()
    {
        throw new RuntimeException("Cannot unserialize singleton");
    }
    public function __destruct()
    {
        if ($this->connection) {
            $this->connection->close();
        }
    }
}

if (session_status() === PHP_SESSION_NONE) {
    session_start();

    if (empty($_SESSION['initiated'])) {
        session_regenerate_id();
        $_SESSION['initiated'] = true;
    }
}

try {
    $db = ConnectToDatabase::getInstance();
    $connection = $db->getConnection();
} catch (RuntimeException $e) {
    die("Database connection error: " . $e->getMessage());
}
