# R509 CA Manager

Consists of several projects to manage a PKI

<!-- TOC depthFrom:2 depthTo:6 withLinks:1 updateOnSave:1 orderedList:0 -->

- [r509-mongoid](#r509-mongoid)
- [r509-ca-http](#r509-ca-http)
- [crl-server](#crl-server)

<!-- /TOC -->


## r509-mongoid

This gem provides a way to store CA configurations, certificates and CRLs in a MongoDB database in a way that they can be used by the r509 library and the r509-ca-http gem in this repository.

## r509-ca-http

This is a derivative work of the [r509/r509-ca-http](https://github.com/r509/r509-ca-http) repository in Github. The modifications are:
* API requests to create, revoke and renew CAs
* Storage of CA configurations, their certificates and CRL info on a Mongo DB through the use of r509-mongoid gem.
* Modification of existing requests to allow stored CA certificates to be encrypted by a password that is received as a parameter on the API request.

## crl-server

This service, deployed as a container, serves CRLs in DER format retrieving them from a Mongo DB where ca-manager is supposed to update them. It is written in Go.

Specifically, when it receives a **/crls/*:name*.crl** request, it will look in the Mongo DB for the CRL for the *:name* CA.
