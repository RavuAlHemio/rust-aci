# aci

Rust client library for the APIC REST API of Cisco ACI

## Usage example

```rust
#[tokio::main]
async fn main() {
    let apic_auth = ApicUsernamePasswordAuth::new(
        "username".into(),
        "password".into(),
    );

    let apic_conn = ApicConnection::new(
        Url::parse("https://apic1.velvetfabric.example.com/").unwrap(),
        apic_auth,
    ).await.unwrap();

    let insts = apic_conn.get_instances(
        "faultInst",
        QuerySettings::new()
    ).await.unwrap();

    for inst in insts {
        println!("{:?}", inst);
    }
}
```

## Features

* username/password authentication
* querying objects by class name or DN
* modifying or deleting objects

## Not yet implemented

* certificate authentication
* WebSocket subscription
