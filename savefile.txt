<?php
/**
* Copyright (c) 2007, Donovan Schonknecht.  All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* - Redistributions of source code must retain the above copyright notice,
*   this list of conditions and the following disclaimer.
* - Redistributions in binary form must reproduce the above copyright
*   notice, this list of conditions and the following disclaimer in the
*   documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*/

/**
* Amazon S3 PHP class
*
* @version 0.1.7
*/
class S3 {
	protected static $accessKey; // AWS Access key
	protected static $secretKey; // AWS Secret key

	// ACL flags
	const ACL_PRIVATE = 'private';
	const ACL_PUBLIC_READ = 'public-read';
	const ACL_PUBLIC_READ_WRITE = 'public-read-write';

	/**
	* Constructor, set AWS access key and secret key
	*
	* @param string $accessKey Access key
	* @param string $secretKey Secret key
	* @param string $magicFile MIME Magic file (for Fileinfo if you use it)
	* @return void
	*/
	function __construct($accessKey = null, $secretKey = null) {
		if (!extension_loaded('curl') && !@dl(PHP_SHLIB_SUFFIX == 'so' ? 'curl.so' : 'php_curl.dll'))
			throw new Exception('Unable to load CURL extension');
		if ($accessKey !== null) self::$accessKey = $accessKey;
		if ($secretKey !== null) self::$secretKey = $secretKey;
	}

	/**
	* Get a list of buckets
	*
	* @return array | false
	*/
	public function listBuckets() {
		$get = new S3Object('GET', '', '');
		$get = $get->getResponse(true);
		if (!isset($get->body)) return false;
		$results = array();
		if (isset($get->body->Buckets))
			foreach ($get->body->Buckets->Bucket as $b)
				$results[] = (string)$b->Name;
		return $get->code == 200 ? $results : false;
	}

	/*
	* Get contents for a bucket
	*
	* @param string $bucket Bucket name
	* @param string $prefix Prefix
	* @param string $marker Marker
	* @param string $maxKeys Max keys
	* @return array | false
	*/
	public function getBucket($bucket, $prefix = null, $marker = null, $maxKeys = null) {
		$get = new S3Object('GET', $bucket, '');
		if ($prefix !== null) $get->setParameter('prefix', $prefix);
		if ($marker !== null) $get->setParameter('marker', $marker);
		if ($maxKeys !== null) $get->setParameter('max-keys', $maxKeys);
		$get = $get->getResponse(true);
		if (!isset($get->body)) return false;
		$results = array();
		if (isset($get->body->Contents))
			foreach ($get->body->Contents as $c)
				$results[(string)$c->Key] = array(
					'time' => strToTime((string)$c->LastModified),
					'hash' => substr((string)$c->ETag, 1, -1),
					'size' => (int)$c->Size
				);
		return $get->code == 200 ? $results : false;
	}

	/**
	* Put a bucket
	*
	* @param string $bucket Bucket name
	* @param constant $acl ACL flag
	* @return mixed
	*/
	public function putBucket($bucket, $acl = self::ACL_PRIVATE) {
		$put = new S3Object('PUT', $bucket, '');
		$put->setAmzHeader('x-amz-acl', $acl);
		$put = $put->getResponse();
		return $put->code == 200 ? true : false;
	}

	/**
	* Delete a bucket
	*
	* @param string $bucket Bucket name
	* @return boolean
	*/
	public function deleteBucket($bucket = '') {
		$delete = new S3Object('DELETE', $bucket);
		$delete = $delete->getResponse();
		return $delete->code == 204 ? true : false;
	}

	/**
	* Get an object
	*
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @return mixed
	*/
	public function getObject($bucket = '', $uri = '') {
		$get = new S3Object('GET', $bucket, $uri);
		$get = $get->getResponse(true);
		return $get->code == 200 ? $get : false;
	}

	/**
	* Get object information
	*
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @param boolean $returnInfo Return response information
	* @return mixed | false
	*/
	public function getObjectInfo($bucket = '', $uri = '', $returnInfo = true) {
		$get = new S3Object('HEAD', $bucket, $uri);
		$get = $get->getResponse(true);
		if ($returnInfo) {
			$headers = array();
			foreach ($get->headers as $header => $value)
				if (preg_match('/^x-amz-meta-.*$/', $header))
					$headers[$header] = is_numeric($value) ? (int)$value : $value;
				elseif ($header == 'Last-Modified')
					$headers['time'] = strToTime($value);
				elseif ($header == 'Content-Length')
					$headers['size'] = (int)$value;
				elseif ($header == 'Content-Type')
					$headers['type'] = $value;
				elseif ($header == 'ETag')
					$headers['hash'] = substr($value, 1, -1);
		}
		return $get->code == 200 ? $returnInfo ? $headers : true : false;
	}

	/**
	* Delete an object
	*
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @return mixed
	*/
	public function deleteObject($bucket = '', $uri = '') {
		$delete = new S3Object('DELETE', $bucket, $uri);
		$delete = $delete->getResponse();
		return $delete->code == 204 ? true : false;
	}

	/**
	* Put an object from a file
	*
	* @param string $file Input file path
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @param constant $acl ACL constant
	* @param array $metaHeaders Array of x-amz-meta-* headers
	* @param string $contentType Content type
	* @return boolean
	*/
	public function putObjectFile($file, $bucket, $uri, $acl = self::ACL_PRIVATE, $metaHeaders = array(), $contentType = null) {
		if (!file_exists($file) || !is_file($file)) {
			trigger_error('S3::putObjectFile(): File does not exist: '.$file, E_USER_WARNING);
			return false;
		}
		$put = new S3Object('PUT', $bucket, $uri);
		$put->file = $file;
		$put->setHeader('Content-Type', $contentType == null ? self::__getMimeType($file) : $contentType);
		$put->setHeader('Content-MD5', base64_encode(md5_file($file, true)));
		$put->setAmzHeader('x-amz-acl', $acl);
		foreach ($metaHeaders as $metaHeader => $metaValue)
			$put->setAmzHeader('x-amz-meta-'.$metaHeader, $metaValue);
		$put = $put->getResponse();
		return $put->code == 200 ? true : false;
	}

	/**
	* Put an object from a string
	*
	* @param string $string Input data
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @param constant $acl ACL constant
	* @param array $metaHeaders Array of x-amz-meta-* headers
	* @param string $contentType Content type
	* @return boolean
	*/
	public function putObjectString($string, $bucket, $uri, $acl = self::ACL_PRIVATE, $metaHeaders = array(), $contentType = 'text/plain') {
		$put = new S3Object('PUT', $bucket, $uri);
		$put->data = $string;
		$put->setHeader('Content-Type', $contentType);
		$put->setHeader('Content-MD5', base64_encode(md5($string, true)));
		$put->setAmzHeader('x-amz-acl', $acl);
		foreach ($metaHeaders as $metaHeader => $metaValue)
			$put->setAmzHeader('x-amz-meta-'.$metaHeader, $metaValue);
		$put = $put->getResponse();
		return $put->code == 200 ? true : false;
	}

	/**
	* Generate the auth header: "Authorization: AWS AccessKey:Signature"
	*
	* This uses the PECL hash extension if loaded.
	*
	* @param string $string String to sign
	* @return string
	*/
	public static function getAuthString($string) {
		if (extension_loaded('hash')) return 'AWS '.self::$accessKey.':'.
			base64_encode(hash_hmac('sha1', $string, self::$secretKey, true));
		else return 'AWS '.self::$accessKey.':'.base64_encode(pack('H*', sha1(
			(str_pad(self::$secretKey, 64, chr(0x00)) ^
			(str_repeat(chr(0x5c), 64))) . pack('H*', sha1(
				(str_pad(self::$secretKey, 64, chr(0x00)) ^
				(str_repeat(chr(0x36), 64))) . $string
			))
		)));
	}

	/**
	* Create the request and return the response
	*
	* This uses the PECL hash extension if loaded.
	*
	* @param S3Object &$obj S3 request object
	* @param boolean $parse Whether or not to parse the response XML
	* @return S3Response
	*/
	public static function getResponse(S3Object &$obj, $parse) {
		$curlReq = curl_init();
		curl_setopt($curlReq, CURLOPT_USERAGENT, 'S3/php-'.phpVersion());
		curl_setopt($curlReq, CURLOPT_SSL_VERIFYHOST, 0);
		curl_setopt($curlReq, CURLOPT_SSL_VERIFYPEER, 0);
		curl_setopt($curlReq, CURLOPT_URL,
			(extension_loaded('openssl') ? 'https://' : 'http://').$obj->headers['Host'].$obj->uri .
			((sizeof($obj->parameters) > 0) ? '?'.http_build_query($obj->parameters) : '')
		);

		$headers = array();
		foreach ($obj->amzHeaders as $header => $value) $headers[] = $header.': '.$value;
		foreach ($obj->headers as $header => $value) $headers[] = $header.': '.$value;

		curl_setopt($curlReq, CURLOPT_HTTPHEADER, $headers);
		curl_setopt($curlReq, CURLOPT_HEADER, true);
		curl_setopt($curlReq, CURLOPT_FOLLOWLOCATION, false);
		curl_setopt($curlReq, CURLOPT_RETURNTRANSFER, true);

		switch ($obj->verb) {
			case 'GET': break;
			case 'PUT':
				if ($obj->file !== false) {
					$fp = fopen($obj->file, 'rb');
					curl_setopt($curlReq, CURLOPT_PUT, true);
					curl_setopt($curlReq, CURLOPT_INFILE, $fp);
					curl_setopt($curlReq, CURLOPT_INFILESIZE, filesize($obj->file));
				} elseif ($obj->data !== false) {
					curl_setopt($curlReq, CURLOPT_CUSTOMREQUEST, 'PUT');
					curl_setopt($curlReq, CURLOPT_POSTFIELDS, $obj->data);
				} else curl_setopt($curlReq, CURLOPT_CUSTOMREQUEST, 'PUT');
			break;
			case 'HEAD':
				curl_setopt($curlReq, CURLOPT_CUSTOMREQUEST, 'HEAD');
				curl_setopt($curlReq, CURLOPT_NOBODY, true);
			break;
			case 'DELETE': curl_setopt($curlReq, CURLOPT_CUSTOMREQUEST, 'DELETE'); break;
			default: break;
		}

		$response = new S3Response;

		$data = explode("\r\n\r\n", curl_exec($curlReq), 2);

		foreach (explode("\n", $data[0]) as $header) {
			if (substr($header, 0, 4) == 'HTTP') continue;
			list($key, $value) = explode(': ', trim($header));
			$response->headers[$key] = $value;
		}

		if ($parse && sizeof($data) > 1)
			$response->body = (isset($response->headers['Content-Type']) &&
			$response->headers['Content-Type'] == 'application/xml') ?
				@simplexml_load_string($data[1]) : $data[1];


		$response->code = curl_getinfo($curlReq, CURLINFO_HTTP_CODE);
		curl_close($curlReq);
		if ($obj->file !== false && isset($fp)) fclose($fp);

		return $response;
	}

	/**
	* Get MIME type for file
	*
	* @param string &$file File path
	* @return string
	*/
	private static function __getMimeType(&$file) {
		$type = false;
		// Fileinfo documentation says fileinfo_open() will use the
		// MAGIC env var for the magic file
		if (extension_loaded('fileinfo') && isset($_ENV['MAGIC']) &&
		($finfo = finfo_open(FILEINFO_MIME, $_ENV['MAGIC'])) !== false) {
			if (($type = finfo_file($finfo, $file)) !== false) {
				// Remove the charset and grab the last content-type
				$type = explode(' ', str_replace('; charset=', ';charset=', $type));
				$type = array_pop($type);
				$type = explode(';', $type);
				$type = array_shift($type);
			}
			finfo_close($finfo);

		// If anyone is still using mime_content_type()
		} elseif (function_exists('mime_content_type'))
			$type = mime_content_type($file);

		if ($type !== false && strlen($type) > 0) return $type;

		// Otherwise do it the old fashioned way
		static $exts = array(
			'jpg' => 'image/jpeg', 'gif' => 'image/gif', 'png' => 'image/png',
			'tif' => 'image/tiff', 'tiff' => 'image/tiff', 'ico' => 'image/x-icon',
			'swf' => 'application/x-shockwave-flash', 'pdf' => 'application/pdf',
			'zip' => 'application/zip', 'gz' => 'application/x-gzip',
			'tar' => 'application/x-tar', 'bz' => 'application/x-bzip',
			'bz2' => 'application/x-bzip2', 'txt' => 'text/plain',
			'asc' => 'text/plain', 'htm' => 'text/html', 'html' => 'text/html',
			'xml' => 'text/xml', 'xsl' => 'application/xsl+xml',
			'ogg' => 'application/ogg', 'mp3' => 'audio/mpeg', 'wav' => 'audio/x-wav',
			'avi' => 'video/x-msvideo', 'mpg' => 'video/mpeg', 'mpeg' => 'video/mpeg',
			'mov' => 'video/quicktime', 'flv' => 'video/x-flv', 'php' => 'text/x-php'
		);
		$ext = strToLower(pathInfo($file, PATHINFO_EXTENSION));
		return isset($exts[$ext]) ? $exts[$ext] : 'application/octet-stream';
	}
}


/**
* Response container
*/
final class S3Response {
	public $code, $headers, $body;
}

/**
* S3 request data object
*/
final class S3Object {
	const DATE_RFC822 = 'D, d M Y H:i:s T';
	public $headers = array(
		'Host' => '', 'Date' => '', 'Content-MD5' => '', 'Content-Type' => ''
	),
	$parameters = array(), $verb, $bucket, $uri, $amzHeaders = array(),
	$resource = '', $file = false, $data = false;

	/**
	* Constructor
	*
	* @param string $verb Verb
	* @param string $bucket Bucket name
	* @param string $uri Object URI
	* @return mixed
	*/
	function __construct($verb, $bucket = '', $uri = '') {
		$this->verb = $verb;
		$this->bucket = $bucket;
		$this->uri = $uri !== '' ? '/'.$uri : '/';
		if ($this->bucket !== '') {
			$bucket = explode('/', $bucket);
			$this->resource = '/'.$bucket[0].$this->uri;
			$this->headers['Host'] = $bucket[0].'.s3.amazonaws.com';
			$this->bucket = implode('/', $bucket);
		} else {
			$this->headers['Host'] = 's3.amazonaws.com';
			if (strlen($this->uri) > 1)
				$this->resource = '/'.$this->bucket.$this->uri;
			else $this->resource = $this->uri;
		}
		$this->headers['Date'] = gmdate(self::DATE_RFC822);
	}

	/**
	* Set request parameter
	*
	* @param string $key Key
	* @param string $value Value
	* @return void
	*/
	public function setParameter($key, $value) {
		$this->parameters[$key] = $value;
	}

	/**
	* Set request header
	*
	* @param string $key Key
	* @param string $value Value
	* @return void
	*/
	public function setHeader($key, $value) {
		$this->headers[$key] = $value;
	}

	/**
	* Set x-amz-meta-* header
	*
	* @param string $key Key
	* @param string $value Value
	* @return void
	*/
	public function setAmzHeader($key, $value) {
		$this->amzHeaders[$key] = $value;
	}

	/**
	* Get the S3 response
	*
	* @return S3Response
	*/
	public function getResponse($parse = false) {
		$amz = array();
		foreach ($this->amzHeaders as $amzHeader => $amzHeaderValue)
			$amz[] = strToLower($amzHeader).':'.$amzHeaderValue;
		$amz = (sizeof($amz) > 0) ? "\n".implode("\n", $amz) : '';
		$this->headers['Authorization'] = S3::getAuthString(
			$this->verb."\n".
			$this->headers['Content-MD5']."\n".
			$this->headers['Content-Type']."\n".
			$this->headers['Date'].$amz."\n".$this->resource
		);
		return S3::getResponse($this, $parse);
	}
}
