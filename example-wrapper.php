#!/usr/local/bin/php
<?php
/**
* $Id$
*
* Note: Although this wrapper works, it would be more efficient to use the S3 class instead
*/

if (!class_exists('S3')) require_once 'S3.php';

// AWS access info
if (!defined('awsAccessKey')) define('awsAccessKey', 'change-this');
if (!defined('awsSecretKey')) define('awsSecretKey', 'change-this');

// Check for CURL
if (!extension_loaded('curl') && !@dl(PHP_SHLIB_SUFFIX == 'so' ? 'curl.so' : 'php_curl.dll'))
	exit("\nERROR: CURL extension not loaded\n\n");

// Pointless without your keys!
if (awsAccessKey == 'change-this' || awsSecretKey == 'change-this')
	exit("\nERROR: AWS access information required\n\nPlease edit the following lines in this file:\n\n".
	"define('awsAccessKey', 'change-me');\ndefine('awsSecretKey', 'change-me');\n\n");


################################################################################


final class S3Wrapper extends S3 {
	private $position = 0, $mode = '', $buffer;

	public function url_stat($path, $flags) {
		self::__getURL($path);
		return (($info = self::getObjectInfo($this->url['host'], $this->url['path'])) !== false) ?
		array('size' => $info['size'], 'mtime' => $info['time'], 'ctime' => $info['time']) : false;
	}

	public function unlink($path) {
		self::__getURL($path);
		return self::deleteObject($this->url['host'], $this->url['path']);
	}

	public function mkdir($path, $mode, $options) {
		self::__getURL($path);
		return self::putBucket($this->url['host'], self::__translateMode($mode));
	}

	public function rmdir($path) {
		self::__getURL($path);
		return self::deleteBucket($this->url['host']);
	}

	public function dir_opendir($path, $options) {
		self::__getURL($path);
		if (($contents = self::getBucket($this->url['host'], $this->url['path'])) !== false) {
			$pathlen = strlen($this->url['path']);
			if (substr($this->url['path'], -1) == '/') $pathlen++;
			$this->buffer = array();
			foreach ($contents as $file) {
				if ($pathlen > 0) $file['name'] = substr($file['name'], $pathlen);
				$this->buffer[] = $file;
			}
			return true;
		}
		return false;
	}

	public function dir_readdir() {
		return (isset($this->buffer[$this->position])) ? $this->buffer[$this->position++]['name'] : false;
	}

	public function dir_rewinddir() {
		$this->position = 0;
	}

	public function dir_closedir() {
		$this->position = 0;
		unset($this->buffer);
	}

	public function stream_close() {
		if ($this->mode == 'w') {
			self::putObject($this->buffer, $this->url['host'], $this->url['path']);
		}
		$this->position = 0;
		unset($this->buffer);
	}

	public function stream_stat() {
		if (is_object($this->buffer) && isset($this->buffer->headers))
			return array(
				'size' => $this->buffer->headers['size'],
				'mtime' => $this->buffer->headers['time'],
				'ctime' => $this->buffer->headers['time']
			);
		elseif (($info = self::getObjectInfo($this->url['host'], $this->url['path'])) !== false)
			return array('size' => $info['size'], 'mtime' => $info['time'], 'ctime' => $info['time']);
		return false;
	}

	public function stream_flush() {
		$this->position = 0;
		return true;
	}

	public function stream_open($path, $mode, $options, &$opened_path) {
		if (!in_array($mode, array('r', 'rb', 'w', 'wb'))) return false; // Mode not supported
		$this->mode = substr($mode, 0, 1);
		self::__getURL($path);
		$this->position = 0;
		if ($this->mode == 'r') {
			if (($this->buffer = self::getObject($this->url['host'], $this->url['path'])) !== false) {
				if (is_object($this->buffer->body)) $this->buffer->body = (string)$this->buffer->body;
			} else return false;
		}
		return true;
	}

	public function stream_read($count) {
		if ($this->mode !== 'r' && $this->buffer !== false) return false;
		$data = substr(is_object($this->buffer) ? $this->buffer->body : $this->buffer, $this->position, $count);
		$this->position += strlen($data);
		return $data;
	}

	public function stream_write($data) {
		if ($this->mode !== 'w') return 0;
		$left = substr($this->buffer, 0, $this->position);
		$right = substr($this->buffer, $this->position + strlen($data));
		$this->buffer = $left . $data . $right;
		$this->position += strlen($data);
		return strlen($data);
	}

	public function stream_tell() {
		return $this->position;
	}

	public function stream_eof() {
		return $this->position >= strlen(is_object($this->buffer) ? $this->buffer->body : $this->buffer);
	}

	public function stream_seek($offset, $whence) {
		switch ($whence) {
			case SEEK_SET:
                if ($offset < strlen($this->buffer->body) && $offset >= 0) {
                    $this->position = $offset;
                    return true;
                } else return false;
            break;
            case SEEK_CUR:
                if ($offset >= 0) {
                    $this->position += $offset;
                    return true;
                } else return false;
            break;
            case SEEK_END:
                $bytes = strlen($this->buffer->body);
                if ($bytes + $offset >= 0) {
                    $this->position = $bytes + $offset;
                    return true;
                } else return false;
            break;
            default: return false;
        }
    }

    private function __getURL($path) {
        $this->url = parse_url($path);
        if (!isset($this->url['scheme']) || $this->url['scheme'] !== 's3') return $this->url;
        if (isset($this->url['user'], $this->url['pass'])) self::setAuth($this->url['user'], $this->url['pass']);
        $this->url['path'] = isset($this->url['path']) ? substr($this->url['path'], 1) : '';
    }

	private function __translateMode($mode) {
		$acl = self::ACL_PRIVATE;
		if (($mode & 0x0020) || ($mode & 0x0004))
			$acl = self::ACL_PUBLIC_READ;
		// You probably don't want to enable public write access
		if (($mode & 0x0010) || ($mode & 0x0008) || ($mode & 0x0002) || ($mode & 0x0001))
			$acl = self::ACL_PUBLIC_READ; //$acl = self::ACL_PUBLIC_READ_WRITE;
		return $acl;
	}
} stream_wrapper_register('s3', 'S3Wrapper');


################################################################################


S3::setAuth(awsAccessKey, awsSecretKey);


$bucketName = uniqid('s3test');

echo "Creating bucket: {$bucketName}\n";
var_dump(mkdir("s3://{$bucketName}"));

echo "\nWriting file: {$bucketName}/test.txt\n";
var_dump(file_put_contents("s3://{$bucketName}/test.txt", "Eureka!"));

echo "\nReading file: {$bucketName}/test.txt\n";
var_dump(file_get_contents("s3://{$bucketName}/test.txt"));

echo "\nContents for bucket: {$bucketName}\n";
foreach (new DirectoryIterator("s3://{$bucketName}") as $b) {
	echo "\t".$b."\n";
}

echo "\nUnlinking: {$bucketName}/test.txt\n";
var_dump(unlink("s3://{$bucketName}/test.txt"));

echo "\nRemoving bucket: {$bucketName}\n";
var_dump(rmdir("s3://{$bucketName}"));


#EOF