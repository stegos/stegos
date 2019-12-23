node_id=$1
json=${@:2}

echo ${json} | ./target/release/stegos -R --formatter json 127.0.0.1:$((3144 + ${node_id})) -t ./dev/node0${node_id}/api.token