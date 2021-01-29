# aci

Rust client library for the APIC REST API of Cisco ACI

## Usage example

```rust
async fn do_query() -> Result<(), Box<dyn std::error::Error>> {
    let apic_auth = ApicUsernamePasswordAuth::new(
        "username".into(),
        "password".into(),
    );

    let apic_conn = ApicConnection::new(
        Url::parse("https://apic1.velvetfabric.example.com/").unwrap(),
        apic_auth,
    ).await?;

    let insts = apic_conn.get_instances(
        "faultInst",
        QuerySettings::new()
    ).await?;

    for inst in insts {
        println!("{:?}", inst);
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    std::process::exit(
        match do_query().await {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("{}", e);
                1
            }
        }
    );
}
```

## Features

* username/password authentication
* querying objects by class name or DN
* modifying or deleting objects

## Not yet implemented

* certificate authentication
* WebSocket subscription
