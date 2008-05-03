#!/usr/local/bin/php
<?php
// S3 class usage

// AWS access info
// define('awsAccessKey', 'change-me');
// define('awsSecretKey', 'change-me');

define('awsAccessKey', '1T4TYJW3DFJY2YFRZDR2');
define('awsSecretKey', 'z90GKSgCCtfwXZnezci+fW7vzrCwUWbS2r39h/71');

//

if (!extension_loaded('fileinfo') && @dl('fileinfo.so')) $_ENV['MAGIC'] = '/usr/share/file/magic';
if (!extension_loaded('curl') && !@dl('curl.so')) exit("ERROR: CURL extension not loaded");
function exit_usage(&$argv) { exit("Usage: {$argv[0]} <bucket name> <file or folder>".PHP_EOL); }
if ($argc <= 2) exit_usage($argv);
elseif (!file_exists($argv[2])) exit("File does not exist: ".$argv[2].PHP_EOL);



include 'S3.php';

class S3Sync extends S3 {
	private $files = array(), $path = null;

	function __construct($accessKey, $secretKey) {
		parent::__construct($accessKey, $secretKey);
	}

	public function add($path) {
		$this->path = realpath($path).'/';
		if (is_file($path)) $this->files[] = $this->path;
		elseif (is_dir($path)) $this->__recursiveList(new DirectoryIterator($this->path));
	}

	public function upload($bucketName, $unlink = false) {
		foreach ($this->files as $k => $file) {
			if ($this->putObjectFile($this->path . $file, $bucketName, $file)) {
				if ($unlink) unlink($this->path . $file);
				unset($this->files[$k]);
			} //else echo 'ERROR: '.$file.PHP_EOL;
		}
	}

	private function __recursiveList(DirectoryIterator $dir) {
		foreach ($dir as $file) {
			if ($dir->isDot() || substr($file->getFilename(), 0, 1) == '.' || substr($file->getFilename(), -1, 1) == '~') continue;

			if ($file->isDir())
				$this->__recursiveList(new DirectoryIterator($file->getPathname()));
			else
				$this->files[] = str_replace($this->path, '', $file->getPathname());
		}
    }


}

try {
	$s3 = new S3Sync(awsAccessKey, awsSecretKey);
	do {
		$s3->add($argv[2]);
		$s3->upload($argv[1], true);
		sleep(3);
	} while (1);
} catch (Exception $e) {
	echo $e->getMessage().PHP_EOL;
}
