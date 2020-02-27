#!/usr/local/bin/php
<?php
/**
 * $Id$
 *
 * S3 class usage
 */

require_once 'vendor/autoload.php';

// File to upload, we'll use this file since it exists
list($uploadFile) = get_included_files();

$region = _getenv('REGION');

$endpoint = new S3EndpointConfig(_getenv('ENDPOINT'), $region);
$endpoint
    ->withPathStyleEnabled(_getenv('USE_PATH_STYLE', 'YES') === 'YES')
    ->withSSLEnabled(_getenv('USE_SSL', 'NO') === 'YES');

$creds = new S3Credentials(_getenv('ACCESS_KEY'), _getenv('SECRET_KEY'));

$bucketName = _getenv('BUCKET');

// Initialise S3
S3::Init($creds, $region, $endpoint);

// Put our file (also with public read access)
echo "S3::putObjectFile(): Copying {$uploadFile} to {$bucketName}/" . baseName($uploadFile) . PHP_EOL;
if (S3::putObjectFile($uploadFile, $bucketName, baseName($uploadFile), S3::ACL_PUBLIC_READ)) {
	echo "S3::putObjectFile(): File copied to {$bucketName}/" . baseName($uploadFile) . PHP_EOL;


	// Get object info
	$info = S3::getObjectInfo($bucketName, baseName($uploadFile));
	echo "S3::getObjectInfo(): Info for {$bucketName}/" . baseName($uploadFile) . ': ' . print_r($info, 1);


	// You can also fetch the object into memory
    var_dump("S3::getObject() to memory", S3::getObject($bucketName, baseName($uploadFile)));


	// Delete our file
	if (S3::deleteObject($bucketName, baseName($uploadFile))) {
		echo "S3::deleteObject(): Deleted file\n";
	} else {
		echo "S3::deleteObject(): Failed to delete file\n";
	}
} else {
	echo "S3::putObjectFile(): Failed to copy file\n";
}

