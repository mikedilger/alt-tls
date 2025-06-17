#!/bin/bash

cargo doc --no-deps
echo "<meta http-equiv=\"refresh\" content=\"0; url=alt_tls/index.html\">" > target/doc/index.html
rm -rf ./docs
mv target/doc ./docs
