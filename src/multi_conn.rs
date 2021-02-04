use std::time::Duration;

use log::{info, warn};
use tokio::sync::RwLock;
use url::Url;

use crate::AciObject;
use crate::auth::ApicAuthenticator;
use crate::conn::{ApicCommError, ApicConnection, QuerySettings};


#[derive(Debug)]
struct ApicConnectionHolder<A: ApicAuthenticator + Clone> {
    pub index: usize,
    pub conn: ApicConnection<A>
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RoundRobinRemedy {
    Refresh,
    Increment,
}


// FIXME: find the right combination of lifetime specifications to solve this using closures
// (i.e. $code is a closure)
macro_rules! round_robin_func {
    (
        $(#[$meta:meta])*
        pub async fn $name:ident($conn:ident, $($arg:ident: $argtype:ty),*) -> $ret:ty $code:block
    ) => {
        $(#[$meta])*
        pub async fn $name(&self, $($arg: $argtype,)*) -> Result<$ret, ApicCommError> {
            let mut start_index: Option<usize> = None;
            loop {
                // with the read lock
                let mut remedy = {
                    let read_holder = self.cur_holder.read()
                        .await;
                    if start_index.is_none() {
                        start_index = Some(read_holder.index);
                    }

                    if read_holder.conn.should_refresh_login().await {
                        RoundRobinRemedy::Refresh
                    } else {
                        // try performing the operation
                        let $conn = &read_holder.conn;
                        let op_res = $code.await;
                        match op_res {
                            Ok(r) => return Ok(r),
                            Err(ApicCommError::Timeout) => RoundRobinRemedy::Increment,
                            Err(e) => return Err(e),
                        }
                    }
                };

                // refresh or increment is necessary
                // grab the write lock
                {
                    let mut write_holder = self.cur_holder.write()
                        .await;
                    if remedy == RoundRobinRemedy::Refresh {
                        match write_holder.conn.refresh().await {
                            Ok(()) => {
                                // retry with the current connection
                                continue;
                            },
                            Err(ApicCommError::Timeout) => {
                                // try with the next
                                remedy = RoundRobinRemedy::Increment;
                            },
                            Err(e) => {
                                // fast path out
                                return Err(e);
                            }
                        }
                    }

                    if remedy == RoundRobinRemedy::Increment {
                        loop {
                            let cur_uri = &self.apic_uris[write_holder.index];
                            warn!("APIC {} is unresponsive", cur_uri);

                            // we have to try the next one
                            write_holder.index = (write_holder.index + 1) % self.apic_uris.len();
                            if write_holder.index == start_index.expect("start index has a value") {
                                // we've tried them all
                                return Err(ApicCommError::Timeout);
                            }

                            let new_uri = &self.apic_uris[write_holder.index];
                            info!("switching to APIC {}", new_uri);

                            let new_conn_res = ApicConnection::new(
                                new_uri.clone(),
                                self.authenticator.clone(),
                                self.timeout,
                            ).await;
                            match new_conn_res {
                                Ok(nc) => {
                                    write_holder.conn = nc;

                                    // break out of inner loop but rerun the outer one
                                    // (to perform the actual operation)
                                    // we can be optimistic here because ApicConnection::new has already talked to the APIC
                                    break;
                                },
                                Err(ApicCommError::Timeout) => {
                                    // rerun the inner loop (next APIC)
                                    continue;
                                }
                                Err(e) => {
                                    // break out
                                    return Err(e);
                                },
                            }
                        }
                    }
                }
            }
        }
    }
}


/// An APIC connection that can fail over between multiple APICs.
#[derive(Debug)]
pub struct ApicMultiConnection<A: ApicAuthenticator + Clone> {
    apic_uris: Vec<Url>,
    authenticator: A,
    timeout: Duration,
    cur_holder: RwLock<ApicConnectionHolder<A>>,
}
impl<A: ApicAuthenticator + Clone> ApicMultiConnection<A> {
    /// Creates a new ApicMultiConnection with the given APIC base URIs.
    pub async fn new(
        apic_uris: Vec<Url>,
        authenticator: A,
        timeout: Duration,
    ) -> Result<ApicMultiConnection<A>, ApicCommError> {
        let mut err = ApicCommError::NoApicSpecified;
        for i in 0..apic_uris.len() {
            info!("initial attempt to use APIC {}", &apic_uris[i]);
            let conn_res = ApicConnection::new(
                apic_uris[i].clone(),
                authenticator.clone(),
                timeout,
            ).await;
            match conn_res {
                Err(e) => {
                    err = e;
                    // continue loop
                },
                Ok(conn) => {
                    // package it and let's go
                    let ach = ApicConnectionHolder {
                        index: i,
                        conn,
                    };
                    let amc = ApicMultiConnection {
                        apic_uris,
                        authenticator,
                        timeout,
                        cur_holder: RwLock::new(ach),
                    };
                    return Ok(amc);
                },
            };
        }

        // the error returned by the last APIC is returned to the caller
        Err(err)
    }

    round_robin_func! {
        /// Return instances of the given class.
        pub async fn get_instances(conn, class_name: &str, query_settings: QuerySettings) -> Vec<AciObject> {
            conn.get_instances(class_name, query_settings.clone())
        }
    }

    round_robin_func! {
        /// Returns the managed object with the given Distinguished Name (or some of its children or
        /// descendants, depending on the query settings).
        pub async fn get_objects(conn, dn: &str, query_settings: QuerySettings) -> Vec<AciObject> {
            conn.get_objects(dn, query_settings.clone())
        }
    }

    round_robin_func! {
        /// Posts (creates or modifies) the supplied managed object in the fabric.
        pub async fn post_object(conn, obj: &AciObject) -> Vec<AciObject> {
            conn.post_object(obj)
        }
    }

    round_robin_func! {
        /// Deletes the object with the given Distinguished Name from the fabric.
        pub async fn delete_object(conn, dn: &str) -> () {
            conn.delete_object(dn)
        }
    }
}
