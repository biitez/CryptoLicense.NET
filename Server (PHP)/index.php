<?php

header('Content-Type: application/json');

define("EncryptionKey", "Your encryption key");
define("CommunicationKey", "Your communication key");

define("DB_HOST","Database host" ); 
define("DB_USER", "Database username"); 
define("DB_PASS", "Database password"); 
define("DB_DATABASE", "Database name" ); 

/*

Credits ;

https://github.com/Biitez
    Discord: bitez#5477
    Telegram: @Biitez

*/

try {
    $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_DATABASE;
    
    $options = [
        \PDO::ATTR_ERRMODE            => \PDO::ERRMODE_EXCEPTION,
        \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
        \PDO::ATTR_EMULATE_PREPARES   => false,
    ];
    
    $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
}
catch (PDOException $ex) {
    die($ex->getMessage());
}

if ($_SERVER['REQUEST_METHOD'] === 'POST')
{
    if (get_header('crypto-access-key') != null)
    {
        if (isset($_GET['session']))
        {
            $SessionID = generateRandomString(15);
            $AccessKey = generateRandomString(25);
            
            $licenseKey = replaceSpace($_POST['License']);
            $stamp = replaceSpace($_POST['Stamp']);
            $accessKey = replaceSpace(get_header('crypto-access-key'));
            
            $accessKeyEncrypted = Encrypt($accessKey);     
            $stampEncrypted = Encrypt($stamp);
            
            $existLicense= "SELECT COUNT(*) FROM CryptoLicenseDB WHERE license = :license";
            $stmt1= $pdo->prepare($existLicense);
            $stmt1->execute(array(":license" => $licenseKey));
            if ($stmt1->fetchColumn() > 0)
            {
                
                $updateSession = $pdo->prepare("UPDATE CryptoLicenseDB SET sessionid = ?, accesskey = ?, stamp = ? WHERE license = ?");
                $updateSession->execute([$SessionID, $AccessKey, $stamp, $licenseKey]);  
                
                http_response_code(200);
                
                $jsonResponse = json_encode(array(
                    'active' => array(
                        'session' => $SessionID,
                        'token' => $accessKeyEncrypted . "?" . $stampEncrypted . "?" . Encrypt($AccessKey))), JSON_PRETTY_PRINT);
                    
                echo $jsonResponse;            
                die();
                
                
            }
            else
            {
                http_response_code(404);
                die();
            }            
        }
    }
    
    if (isset($_GET['validate']))
    {
        $PublicIP = file_get_contents("http://ipecho.net/plain");
        $HWID = replaceSpace($_POST['HWID']);
            
        $SessionID = $_GET['validate'];
        $accessKey = replaceSpace(get_header('crypto-license-access-key'));
            
        $ExistSession = "SELECT COUNT(*) FROM CryptoLicenseDB WHERE sessionid = ? AND accesskey = ?";
        $stmt1= $pdo->prepare($ExistSession);
        $stmt1->execute([$SessionID, $accessKey]);
        if ($stmt1->fetchColumn() > 0)
        {
            $SelectLicenseInfo = $pdo->prepare("SELECT * from CryptoLicenseDB WHERE sessionid = ? AND accesskey = ?");
            $SelectLicenseInfo->execute([$SessionID, $accessKey]);                
                
            while ($rows = $SelectLicenseInfo->fetch())
            {
                $license = $rows['license'];
                $use_limit = $rows['multi'];
                $current_hwids = $rows['hwid'];
                $saved_stamp = $rows['stamp'];
                $rankLicense = $rows['rank'];
                $banned = $rows['banned'];
                $hwids_arr = explode(',', $current_hwids);
                $hwids_size = count($hwids_arr);                    
            }
                
            $stmt = $pdo->prepare("UPDATE CryptoLicenseDB SET sessionid=?, accesskey=?, stamp=? WHERE license=?");
            if (!$stmt->execute(['', '', '', $license]))
            {
                server_error_exit();
            }
            else
            {
                if ($banned == "1")
                {
                    http_response_code(403);
                    die();
                }
                
                if (empty($current_hwids) || ($hwids_size < $use_limit && !hash_in_array($HWID, $hwids_arr)))
                {
                    $stmt = $pdo->prepare("UPDATE CryptoLicenseDB SET hwid=?, ipaddress=? WHERE license=?");
                    $hwids_new = empty($current_hwids) ? $HWID : ($current_hwids . "," . $HWID);
                        
                    if (!$stmt->execute([$hwids_new, $PublicIP, $license]))
                    {
                        server_error_exit();
                    }
                    else
                    {
                        http_response_code(200);
                        
                        $jsonValidLicense = json_encode(array(
                            'licenseInfo' => array(
                                'verifyStamp' => Encrypt($saved_stamp),
                                'verifyAccessKey' => Encrypt($accessKey),
                                'Rank' => Encrypt($rankLicense))), JSON_PRETTY_PRINT);
                            
                        echo $jsonValidLicense;
                        die();
                            
                    }
                }
                else if (hash_equals($current_hwids, $HWID) || hash_in_array($HWID, $hwids_arr))
                {
                    http_response_code(200);
                        
                    $jsonValidLicense = json_encode(array(
                        'licenseInfo' => array(
                            'verifyStamp' => Encrypt($saved_stamp),
                            'verifyAccessKey' => Encrypt($accessKey),
                            'Rank' => Encrypt($rankLicense))), JSON_PRETTY_PRINT);
                        
                    echo $jsonValidLicense;
                    die();                
                }
                else if (!hash_equals($current_hwids, $HWID && !hash_in_array($HWID, $hwids_arr)))
                {
                    http_response_code(401);
                    die();
                }
                else
                {
                    bad_request_exit();
                }                
            }
        }
        else
        {
            http_response_code(400);
            die();
        }
    }    
}
else
{
    bad_request_exit();
}

function hash_in_array($hash, array $arr)
{
    $in = false;

    foreach ($arr as $item) 
    {
        if (hash_equals($hash, $item)) 
        {
            $in = true;
            break;
        }
    }

    return $in;
}

function Encrypt($string)
{
    $plaintext = $string;
    $password = base64_decode(constant('EncryptionKey'));
    $method = 'aes-256-cbc';
    $password = substr(hash('sha256', $password, true), 0, 32);
    $iv = base64_decode(constant('CommunicationKey'));
    $encrypted = base64_encode(openssl_encrypt($plaintext, $method, $password, OPENSSL_RAW_DATA, $iv));
    return $encrypted;
}

function Decrypt($string)
{
    $plaintext = $string;
    $password = base64_decode(constant('EncryptionKey'));
    $method = 'aes-256-cbc';
    $password = substr(hash('sha256', $password, true), 0, 32);
    $iv = base64_decode(constant('CommunicationKey'));
    $decrypted = openssl_decrypt(base64_decode($plaintext), $method, $password, OPENSSL_RAW_DATA, $iv);
    return $decrypted;
}

function generateRandomString($length = 15)
{
    return substr(sha1(rand()), 0, $length);
}

function server_error_exit()
{
    http_response_code(503);
    die();
}

function bad_request_exit()
{
    http_response_code(400);
    die();
}

function replaceSpace($data) 
{
    return str_replace(' ', '+', str_replace("%20", "+", $data));
}

function get_header($headerName)
{
    $headers = getallheaders();
    return isset($headerName) ? $headers[$headerName] : null;
}

?>
