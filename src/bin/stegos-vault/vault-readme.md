# Stegos vault

Stegos vault provide api for managing cold storage specific for exchanges.
Stegos vault use the same websocket api like regular stegosd. For more detail read https://docs.stegos.com/developers/websocket_api/.

This api extend https://docs.stegos.com/developers/exchange_integration/  and encapsulate "Output explorer", "Private stegosd node" and " Cold wallet".

The only remaining parts is:
1) Online stegosd node, which should be connected to network, and provide websocket api to some local zone.
2) And stegos-vault, which would operate with online node websocket api, and provide high level api to manage funds.

## Configuration 

Stegos vault will read configuration from one of three location in specific order:
1. From CLI `--config` paramaeter
2. In "currrent" dirrectory : `$PWD/stegosd.toml`
3. From user application data folder: `/home/[USER]/.local/share/stegos-vault/stegos-vault.toml`

Config format is next:

```
node_address = "127.0.0.1:3145"
node_token_path = "/home/[USER]/.local/share/stegos/api.token"

[general]
chain = "testnet"
data_dir = "/home/[USER]/.local/share/stegos-vault"
api_endpoint = "127.0.0.1:4145"
```

`node_address` - is endpoint address of online node.
`node_token_path` - path to online node token.
`chain` - chain history that would be used, can be `testnet` `mainnet` or local `dev`.
`data_dir` - directory to save accounts, operation history and other vault-specific data.
`api_endpoint` - stegos-vault api listen address.

## Api request response

1. Unlock vault, for future usage. This api can be used to init account. If account was created flag `created` would be set to `true` in response.

### Request:
```
{
"type": "unseal",
"password": "", // string for password used to encrypt keys on disk.
}
```


### Response:

```
{
"type":"unsealed",
"created": "true", // boolean, that represents if main account was created, or found on disk
},
```

2. Create account specific for user. That will wait for PublicPayments and notify if balance changes.

```
{
"type": "create_user",
"account_id": "", // string for identify user account, can be user name, or other id.
},
```

### Response:
```
{
"type": "created_user",
"account_id": "", // string for identify user account, can be user name, or other id.
},
```

3. Get user public key.

### Request:
```
{
"type": "get_user",
"account_id": "", // stringfor identify user account, can be user name, or other id.
}
```

### Response:

```
{
"type": "get_user",
"account_id": "", // stringfor identify user account, can be user name, or other id.
"public_key": "", // user wallet PublicKey, which is used to deposit money.
}
```

4. Get public keys of all known users.

### Request:
```
{
"type": "get_users",
}

```

### Response:

```
{
"type": "get_users",
"main": "", // Cold wallet account public key, which is used for withdraw money.
"list": [{
    account_id: "", // stringfor identify user account, can be user name, or other id.
    public_key: "", // user wallet PublicKey, which is used to deposit money.
},..],
```

5. Remove user account

### Request:
```
{
"type": "remove_users",
"account_id": "", // string for identify user account, can be user name, or other id.
}

```

### Response:
```
{
"type": "removed_users",
"account_id": "", // string for identify user account, can be user name, or other id.
"public_key": "", // user wallet PublicKey, which is used to deposit money.
}
```

6. Subscribe for notifications

### Request:
```
{
"type": "subscribe",
"epoch": u64, // Numeric epoch where last notification was processed 
}
```

### Response:

```
{
"type": "subscribed",
}
```
7. 

### Request:
```
{
"type": "withdraw",
"public_key": "", // recipient PublicKey, which is used to withdraw money from cold account.
"amount": "", // 
"payment_fee": i64,
"public": bool,
}

```

### Response:

```
{
"type": "WithdrawCreated",
"outputs_hashes": [
    output_hash, // hash that represent outputs.
]
}
```

8. Get recovery phrase


### Request:
```
{
  "type": "recovery_info"
  "account_id": "1", // optional account_id, if not passed, getting recovery phrase for main cold_storage account
}
```

### Response:

```
{
  "account_id": "1", // if skiped or nill ,then it main account
  "type": "recovery",
  "recovery": "swear praise ginger oxygen anchor ten small planet crime cave fold chuckle foot dragon decorate guess poverty grass crew depend define twice mother update",
}

```


## Errors handling

If something happen during request processing, response with error would be created.

```
{
"type": "error",
"code": "", // unique id of error
"error": "", // string represented error message.
}
```

## Notifications

After subscribing for notifications, you can receive next possible notifications:
1. Block processed:
```
{
"type": "block_processed",
"list": [{ // list of users updates
    "update_type": "user_deposit_received" | "user_deposit_confirmed", // Type of user update
    "public_key": "", // user account public key,
    "id": "", // string represented account id of user.
    "amount": i64, // Amount of 
}.
]
"amount": "", // if balance was changed, new amount should be present.
}
```

2. Notification disconnected by server reason:
```
{
"type": "disconnected",
"error": "", // Reason why notification was disconnected.
"code": ""// numeric code of the error
}
```

