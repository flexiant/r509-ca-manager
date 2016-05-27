#!/usr/bin/env puma

rackup 'config.ru'

environment ENV['RACK_ENV']

daemonize false

threads 0, 16

fqdn = ENV['CA_MANAGER_SERVER_NAME'] || %x(hostname)
ssl_bind '0.0.0.0', '9292', {
  key: "certs/#{fqdn}.key",
  cert: "certs/#{fqdn}.crt",
}
