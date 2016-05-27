#!/bin/bash
thin -p 9292 --rackup config.ru $* start
