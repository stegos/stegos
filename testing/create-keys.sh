#!/usr/bin/env bash

openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -outform DER -pubout -out public-key.der
openssl pkcs8 -in private.pem -topk8 -nocrypt -outform der -out private-key.pk8
rm private.pem 