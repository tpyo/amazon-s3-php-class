<?php

use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\GuzzleException;

class S3GuzzleTest extends S3BaseTest {

    /**
     * @throws GuzzleException
     */
    public function testPublicFileExistsOnS3() {
        $resp = $this->getGuzzleClient()->get(self::PUBLIC_OBJECT);
        $this->assertEquals(200, $resp->getStatusCode());
    }
    /**
     * @throws GuzzleException
     */
    public function testPrivateFileIsNotAccessible() {
        try {
            $this->getGuzzleClient()->get(self::PRIVATE_OBJECT);
        }
        catch (ClientException $ex) {
            $this->assertEquals(403, $ex->getResponse()->getStatusCode());
        }
    }
}
