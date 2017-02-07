# Amazon S3 PHP Class

## Usage

OO method (e,g; $s3->getObject(...)):

```php
$s3 = new S3($awsAccessKey, $awsSecretKey);
```

Statically (e,g; S3::getObject(...)):

```php
S3::setAuth($awsAccessKey, $awsSecretKey);
```

<div style="margin: 25px;">
<a href="https://rapidapi.com/package/AmazonS3/functions?utm_source=AmazonS3GitHub-PHP&utm_medium=button&utm_content=Vendor_GitHub" style="
    all: initial;
    background-color: #498FE1;
    border-width: 0;
    border-radius: 5px;
    padding: 10px 20px;
    color: white;
    font-family: 'Helvetica';
    font-size: 12pt;
    background-image: url(https://scdn.rapidapi.com/logo-small.png);
    background-size: 25px;
    background-repeat: no-repeat;
    background-position-y: center;
    background-position-x: 10px;
    padding-left: 44px;
    cursor: pointer;">
  Run now on <b>RapidAPI</b>
</a>
</div>

### Object Operations

#### Uploading objects

Put an object from a file:

```php
S3::putObject(S3::inputFile($file, false), $bucketName, $uploadName, S3::ACL_PUBLIC_READ)
```

Put an object from a string and set its Content-Type:

```php
S3::putObject($string, $bucketName, $uploadName, S3::ACL_PUBLIC_READ, array(), array('Content-Type' => 'text/plain'))
```

Put an object from a resource (buffer/file size is required - note: the resource will be fclose()'d automatically):

```php
S3::putObject(S3::inputResource(fopen($file, 'rb'), filesize($file)), $bucketName, $uploadName, S3::ACL_PUBLIC_READ)
```

#### Retrieving objects

Get an object:

```php
S3::getObject($bucketName, $uploadName)
```

Save an object to file:

```php
S3::getObject($bucketName, $uploadName, $saveName)
```

Save an object to a resource of any type:

```php
S3::getObject($bucketName, $uploadName, fopen('savefile.txt', 'wb'))
```

#### Copying and deleting objects

Copy an object:

```php
S3::copyObject($srcBucket, $srcName, $bucketName, $saveName, $metaHeaders = array(), $requestHeaders = array())
```

Delete an object:

```php
S3::deleteObject($bucketName, $uploadName)
```

### Bucket Operations

Get a list of buckets:

```php
S3::listBuckets()  // Simple bucket list
S3::listBuckets(true)  // Detailed bucket list
```

Create a bucket:

```php
S3::putBucket($bucketName)
```

Get the contents of a bucket:

```php
S3::getBucket($bucketName)
```

Delete an empty bucket:

```php
S3::deleteBucket($bucketName)
```

