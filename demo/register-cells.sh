echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "register",
    "params": [
        {
            "script": {
                "code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                "hash_type": "type",
                "args": "0xc13fd4f1bd05834ebf448685e6d086140462dc10"
            },
            "script_type": "lock"
        },
        "0x0"
    ]
}' \
| curl -H 'content-type: application/json' -d @- \
http://emitter-rpc-url

echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "register",
    "params": [
        {
            "script": {
                "code_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "hash_type": "data",
                "args": "0x"
            },
            "script_type": "lock"
        },
        "0x0"
    ]
}' \
| curl -H 'content-type: application/json' -d @- \
http://emitter-rpc-url


echo '{
    "id": 2,
    "jsonrpc": "2.0",
    "method": "register",
    "params": [
        {
            "script": {
                "code_hash": "0xd23761b364210735c19c60561d213fb3beae2fd6172743719eff6920e020baac",
                "hash_type": "type",
                "args": "0x00016091d93dbab12f16640fb3a0a8f1e77e03fbc51c"
            },
            "script_type": "lock"
        },
        "0x0"
    ]
}' \
| curl -H 'content-type: application/json' -d @- \
http://emitter-rpc-url