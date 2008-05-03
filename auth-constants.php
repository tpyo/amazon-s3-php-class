<?php

// AWS access info
define('awsAccessKey', '1T4TYJW3DFJY2YFRZDR2');
define('awsSecretKey', 'z90GKSgCCtfwXZnezci+fW7vzrCwUWbS2r39h/71');



/*

# Create log bucket:
./s3curl.pl --id personal --acl log-delivery-write --put /dev/null -- -s -v http://s3.amazonaws.com/logs.undesigned.org.za

# Enable logging:
./s3curl.pl --id personal -- -s -v "http://s3.amazonaws.com/s3.undesigned.org.za?logging" > s3.sample.set-logging


*/