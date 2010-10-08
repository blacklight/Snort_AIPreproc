#!/bin/sh

echo "Content-Type: text/html"
echo
echo "<h1>LOL</h1>"
echo "Query string: <b>$QUERY_STRING</b><br>"
echo "Accept: <b>$HTTP_ACCEPT</b><br>"
echo "User-Agent: <b>$HTTP_USER_AGENT</b><br>"
echo "Client addr : <b>$REMOTE_ADDR</b><br>"

