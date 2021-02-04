# aci

Rust client library for the APIC REST API of Cisco ACI

## Usage example

Cargo.toml:

```toml
[dependencies]
aci = { version = "0.1" }
tokio = { version = "1.1", features = ["full"] }
url = { version = "2.2" }
```

src/main.rs:

```rust
use aci::auth::ApicUsernamePasswordAuth;
use aci::conn::{ApicConnection, QuerySettings};
use url::Url;


async fn do_query() -> Result<(), Box<dyn std::error::Error>> {
    let apic_auth = ApicUsernamePasswordAuth::new(
        "username".into(),
        "password".into(),
    );

    let apic_conn = ApicConnection::new(
        Url::parse("https://apic1.velvetfabric.example.com/").unwrap(),
        apic_auth,
        std::time::Duration::from_secs(10),
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
