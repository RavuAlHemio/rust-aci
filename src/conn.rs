use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::error::Error;
use std::marker::PhantomData;

use bitflags::bitflags;
use hyper::{Body, Client, Request, StatusCode};
use hyper::client::HttpConnector;
use hyper_tls::HttpsConnector;
use json::JsonValue;
use log::debug;
use url::Url;

use crate::{AciObject, AciObjectError};
use crate::auth::{ApicAuthenticator, ApicAuthenticatorData};
use crate::error::ApicCommError;


/// Performs a JSON request against an APIC-like server.
///
/// This is a very low-level operation. Unless you are implementing a custom ApicAuthenticator, you
/// probably want to use the associated functions of ApicConnection.
pub async fn perform_json_request<C>(
    client: &Client<C, Body>,
    uri: Url,
    method: &str,
    headers: &HashMap<String, String>,
    body: Option<JsonValue>,
) -> Result<JsonValue, ApicCommError>
        where C: 'static + Clone + hyper::client::connect::Connect + Send + Sync {
    debug!("{} {}", method, uri);

    let body_bytes: Option<Vec<u8>> = body
        .map(|b| b.dump().bytes().collect());

    let mut bldr = Request::builder()
        .method(method)
        .uri(uri.as_str());
    for (k, v) in headers {
        bldr = bldr.header(k, v);
    }
    let req_res = if let Some(bb) = body_bytes {
        bldr.header("Content-Type", "application/json")
            .body(Body::from(bb))
    } else {
        bldr.body(Body::empty())
    };
    let req = req_res
        .map_err(|e| ApicCommError::ErrorAssemblingRequest(e))?;

    let response = client.request(req)
        .await
        .map_err(|e| ApicCommError::ErrorObtainingResponse(e))?;
    if response.status() != StatusCode::OK {
        return Err(ApicCommError::ErrorResponse(response).into());
    }

    let (_response_parts, response_body) = response.into_parts();
    let response_bytes = hyper::body::to_bytes(response_body)
        .await
        .map_err(|e| ApicCommError::ErrorObtainingResponse(e))?;
    let response_str = std::str::from_utf8(&response_bytes)
        .map_err(|e| ApicCommError::InvalidUtf8(e))?;
    let response_json = json::parse(response_str)
        .map_err(|e| ApicCommError::InvalidJson(e))?;

    Ok(response_json)
}

/// Converts a JSON value returned by the APIC into a vector of ACI objects.
///
/// This JSON value is an object with an `"imdata"` key containing a list of single ACI objects.
pub fn json_to_aci_objects(body: JsonValue) -> Result<Vec<AciObject>, AciObjectError> {
    let mut ret = Vec::new();

    let imdata = &body["imdata"];
    if imdata.is_null() {
        return Err(AciObjectError::NoImdata);
    }
    for entry in imdata.members() {
        let aci_obj = entry.try_into()?;
        ret.push(aci_obj);
    }

    Ok(ret)
}


/// Allows an object to return the corresponding REST API query key and value.
trait RestQueryParam {
    /// Returns the key to pass as a GET argument to the REST API.
    fn rest_key(&self) -> String;

    /// Returns the value to pass as a GET argument to the REST API.
    fn rest_value(&self) -> String;
}


/// Defines the scope of a query, i.e. which part of the object tree to search relative to the base
/// Distinguished Name (DN) specified.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum QueryTarget {
    /// Consider the object with the specified DN.
    ConsiderSelf,

    /// Consider the children of the object with the specified DN.
    ConsiderChildren,

    /// Consider the descendants of the object with the specified DN, i.e. its children, their
    /// children, their children, etc.
    ConsiderSubtree,
}
impl RestQueryParam for QueryTarget {
    fn rest_key(&self) -> String { String::from("query-target") }

    /// Returns the value to pass as a GET argument to the REST API.
    fn rest_value(&self) -> String {
        match &self {
            QueryTarget::ConsiderSelf => "self",
            QueryTarget::ConsiderChildren => "children",
            QueryTarget::ConsiderSubtree => "subtree",
        }.into()
    }
}


/// Defines the scope of a query's return value, i.e. which part of the object tree to return for
/// each object that has been found.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ResponseSubtree {
    /// Return only the found object.
    ReturnSelf,

    /// Return only the found object's children.
    ReturnChildren,

    /// Return the found object and its descendants (i.e. its children, their children, their
    /// children, etc.).
    ReturnFull,
}
impl RestQueryParam for ResponseSubtree {
    /// Returns the key to pass as a GET argument to the REST API.
    fn rest_key(&self) -> String { "rsp-subtree".into() }

    /// Returns the value to pass as a GET argument to the REST API.
    fn rest_value(&self) -> String {
        match &self {
            ResponseSubtree::ReturnSelf => "self",
            ResponseSubtree::ReturnChildren => "children",
            ResponseSubtree::ReturnFull => "full",
        }.into()
    }
}


bitflags! {
    /// Defines which additional objects should be returned for each object.
    pub struct ResponseSubtreeInclude: u64 {
        /// Return subtrees with the history of user modifications to managed objects.
        const AUDIT_LOGS = 0x0001;

        /// Return subtrees with event history information.
        const EVENT_LOGS = 0x0002;

        /// Return subtrees with currently active faults.
        const FAULTS = 0x0004;

        /// Return subtrees with fault history information.
        const FAULT_RECORDS = 0x0008;

        /// Return subtrees with current health information.
        const HEALTH = 0x0010;

        /// Return subtrees with health history information.
        const HEALTH_RECORDS = 0x0020;

        /// Return relation-related subtrees.
        const RELATIONS = 0x0040;

        /// Return statistics-related subtrees.
        const STATS = 0x0080;

        /// Return task-related subtrees.
        const TASKS = 0x0100;

        /// Return a count of matching subtrees but not the subtrees themselves
        const COUNT = 0x0001_0000_0000;

        /// Return only the requested subtree information, no other top-level managed object
        /// information.
        const NO_SCOPED = 0x0002_0000_0000;

        /// Return only those managed objects that have subtrees matching the specified category.
        const REQUIRED = 0x0004_0000_0000;
    }
}
impl RestQueryParam for ResponseSubtreeInclude {
    /// Returns the key to pass as a GET argument to the REST API.
    fn rest_key(&self) -> String { "rsp-subtree-include".into() }

    /// Returns the value to pass as a GET argument to the REST API.
    fn rest_value(&self) -> String {
        let mut bits: Vec<&'static str> = Vec::new();
        if self.contains(ResponseSubtreeInclude::AUDIT_LOGS) {
            bits.push("audit-logs");
        }
        if self.contains(ResponseSubtreeInclude::EVENT_LOGS) {
            bits.push("event-logs");
        }
        if self.contains(ResponseSubtreeInclude::FAULTS) {
            bits.push("faults");
        }
        if self.contains(ResponseSubtreeInclude::FAULT_RECORDS) {
            bits.push("fault-records");
        }
        if self.contains(ResponseSubtreeInclude::HEALTH) {
            bits.push("health");
        }
        if self.contains(ResponseSubtreeInclude::HEALTH_RECORDS) {
            bits.push("health-records");
        }
        if self.contains(ResponseSubtreeInclude::RELATIONS) {
            bits.push("relations");
        }
        if self.contains(ResponseSubtreeInclude::STATS) {
            bits.push("stats");
        }
        if self.contains(ResponseSubtreeInclude::TASKS) {
            bits.push("tasks");
        }
        if self.contains(ResponseSubtreeInclude::COUNT) {
            bits.push("count");
        }
        if self.contains(ResponseSubtreeInclude::NO_SCOPED) {
            bits.push("no-scoped");
        }
        if self.contains(ResponseSubtreeInclude::REQUIRED) {
            bits.push("required");
        }
        bits.join(",")
    }
}


/// Defines which properties to include in the response.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ResponsePropertyInclude {
    /// Return all properties of each managed object.
    All,

    /// Return only the naming properties of each managed object.
    NamingOnly,

    /// Return only the configurable properties of each managed object.
    ConfigOnly,
}
impl RestQueryParam for ResponsePropertyInclude {
    /// Returns the key to pass as a GET argument to the REST API.
    fn rest_key(&self) -> String { "rsp-prop-include".into() }

    /// Returns the value to pass as a GET argument to the REST API.
    fn rest_value(&self) -> String {
        match &self {
            ResponsePropertyInclude::All => "all",
            ResponsePropertyInclude::NamingOnly => "naming-only",
            ResponsePropertyInclude::ConfigOnly => "config-only",
        }.into()
    }
}


/// Allows query settings to be set before a query is performed.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct QuerySettings {
    query_target: QueryTarget,
    query_target_filter: Option<String>,
    response_subtree: ResponseSubtree,
    response_subtree_classes: Option<HashSet<String>>,
    response_subtree_include: Option<ResponseSubtreeInclude>,
    response_property_include: ResponsePropertyInclude,
}
impl QuerySettings {
    /// Creates a new QuerySettings instance with common defaults.
    pub fn new() -> QuerySettings {
        QuerySettings {
            query_target: QueryTarget::ConsiderSubtree,
            query_target_filter: None,
            response_subtree: ResponseSubtree::ReturnFull,
            response_subtree_classes: None,
            response_subtree_include: None,
            response_property_include: ResponsePropertyInclude::All,
        }
    }

    /// Sets the target of this query and returns the QuerySettings object.
    pub fn query_target(mut self, query_target: QueryTarget) -> Self {
        self.query_target = query_target;
        self
    }

    /// Sets the target filter of this query and returns the QuerySettings object.
    pub fn query_target_filter(mut self, query_target_filter: &str) -> Self {
        self.query_target_filter = Some(String::from(query_target_filter));
        self
    }

    /// Unsets the target filter of this query and returns the QuerySettings object.
    pub fn query_target_filter_any(mut self) -> Self {
        self.query_target_filter = None;
        self
    }

    /// Sets the form of the response subtree and returns the QuerySettings object.
    pub fn response_subtree(mut self, response_subtree: ResponseSubtree) -> Self {
        self.response_subtree = response_subtree;
        self
    }

    /// Sets which subtree classes to return and returns the QuerySettings object.
    pub fn response_subtree_classes<S: AsRef<str>>(mut self, response_subtree_classes: &[S]) -> Self {
        self.response_subtree_classes = Some(
            response_subtree_classes
                .iter()
                .map(|s| String::from(s.as_ref()))
                .collect()
        );
        self
    }

    /// Sets that all subtree classes are to be returned and returns the QuerySettings object.
    pub fn response_subtree_classes_all(mut self) -> Self {
        self.response_subtree_classes = None;
        self
    }

    /// Sets which subtree objects to return and returns the QuerySettings object.
    pub fn response_subtree_include(mut self, response_subtree_include: ResponseSubtreeInclude) -> Self {
        self.response_subtree_include = Some(response_subtree_include);
        self
    }

    /// Sets that all subtree objects are to be returned and returns the QuerySettings object.
    pub fn response_subtree_include_all(mut self) -> Self {
        self.response_subtree_include = None;
        self
    }

    /// Sets which kind of properties is to be returned and returns the QuerySettings object.
    pub fn response_property_include(mut self, response_property_include: ResponsePropertyInclude) -> Self {
        self.response_property_include = response_property_include;
        self
    }

    pub fn to_aci_keys_values(self) -> HashMap<String, String> {
        let mut keys_values = HashMap::new();

        keys_values.insert(self.query_target.rest_key(), self.query_target.rest_value());
        if let Some(qtf) = self.query_target_filter {
            keys_values.insert(String::from("query-target-filter"), qtf);
        }
        keys_values.insert(self.response_subtree.rest_key(), self.response_subtree.rest_value());
        if let Some(rsc) = self.response_subtree_classes {
            let classes_str = rsc.iter()
                .map(|s| s.as_ref())
                .collect::<Vec<&str>>()
                .join(",");
            keys_values.insert(String::from("rsp-subtree-class"), classes_str);
        }
        if let Some(rsi) = self.response_subtree_include {
            keys_values.insert(rsi.rest_key(), rsi.rest_value());
        }
        keys_values.insert(self.response_property_include.rest_key(), self.response_property_include.rest_value());

        keys_values
    }
}


/// A connection to an Application Policy Infrastructure Controller (APIC).
pub struct ApicConnection<A, AE>
        where A: ApicAuthenticator<AE>, AE: Error {
    base_uri: Url,
    client: Client<HttpsConnector<HttpConnector>, Body>,
    authenticator: A,
    auth_data: Option<ApicAuthenticatorData>,
    _auth_error_type: PhantomData<AE>,
}
impl<A, AE> ApicConnection<A, AE>
        where A: ApicAuthenticator<AE>, AE: Error {
    /// Creates a new APIC connection object.
    pub async fn new(
        base_uri: Url,
        authenticator: A,
    ) -> Result<Self, AE> {
        let https = HttpsConnector::new();
        let client = Client::builder()
            .build::<_, Body>(https);
        let mut me = Self {
            base_uri,
            client,
            authenticator,
            auth_data: None,
            _auth_error_type: PhantomData::default(),
        };
        me.login().await?;
        Ok(me)
    }

    /// Returns whether successful authentication with the APIC was performed at least once.
    pub fn auth_performed(&self) -> bool {
        self.auth_data.is_some()
    }

    /// Authenticates with the APIC, creating a new session.
    pub async fn login(&mut self) -> Result<(), AE> {
        let auth_data = self.authenticator
            .login(&self.client, &self.base_uri)
            .await?;
        self.auth_data = Some(auth_data);
        Ok(())
    }

    /// Refreshes the current authentication session with the APIC.
    pub async fn refresh(&mut self) -> Result<(), AE> {
        let current_auth_data = self.auth_data.as_ref()
            .expect("is authenticated");
        let auth_data = self.authenticator
            .refresh(&self.client, &self.base_uri, current_auth_data)
            .await?;
        self.auth_data = Some(auth_data);
        Ok(())
    }

    /// Returns the instances of the given class.
    pub async fn get_instances(
        &self,
        class_name: &str,
        query_settings: QuerySettings,
    ) -> Result<Vec<AciObject>, ApicCommError> {
        let query_settings_map = query_settings.to_aci_keys_values();

        let mut query_uri = self.base_uri.clone();

        {
            let mut segs = query_uri.path_segments_mut()
                .expect("base URI does not have editable path segments");
            segs.push("api");
            segs.push("class");
            segs.push(&format!("{}.json", class_name));
        }

        for (k, v) in &query_settings_map {
            query_uri.query_pairs_mut()
                .append_pair(k, v);
        }

        let auth_data = self.auth_data.as_ref()
            .expect("authenticated at least once");
        let mut headers = auth_data.as_headers();
        headers.insert("Accept".into(), "application/json".into());

        let json_value = perform_json_request(
            &self.client,
            query_uri,
            "GET",
            &headers,
            None,
        ).await?;
        let aci_objects = json_to_aci_objects(json_value)
            .map_err(|aoe| ApicCommError::InvalidAciObject(aoe))?;
        Ok(aci_objects)
    }

    /// Returns the managed object with the given Distinguished Name (or some of its children or
    /// descendants, depending on the query settings).
    pub async fn get_objects(
        &self,
        dn: &str,
        query_settings: QuerySettings,
    ) -> Result<Vec<AciObject>, ApicCommError> {
        let query_settings_map = query_settings.to_aci_keys_values();

        let mut query_uri = self.base_uri.clone();

        {
            let mut segs = query_uri.path_segments_mut()
                .expect("base URI does not have editable path segments");
            segs.push("api");
            segs.push("mo");
            segs.push(&format!("{}.json", dn));
        }

        for (k, v) in &query_settings_map {
            query_uri.query_pairs_mut()
                .append_pair(k, v);
        }

        let auth_data = self.auth_data.as_ref()
            .expect("authenticated at least once");
        let mut headers = auth_data.as_headers();
        headers.insert("Accept".into(), "application/json".into());

        let json_value = perform_json_request(
            &self.client,
            query_uri,
            "GET",
            &headers,
            None,
        ).await?;
        let aci_objects = json_to_aci_objects(json_value)
            .map_err(|aoe| ApicCommError::InvalidAciObject(aoe))?;
        Ok(aci_objects)
    }

    /// Posts (creates or modifies) the supplied managed object in the fabric.
    pub async fn post_object(
        &self,
        obj: &AciObject,
    ) -> Result<Vec<AciObject>, ApicCommError> {
        let mut query_uri = self.base_uri.clone();

        {
            let mut segs = query_uri.path_segments_mut()
                .expect("base URI does not have editable path segments");
            segs.push("api");
            segs.push("mo");
            segs.push(&format!("{}.json", obj.dn()));
        }

        let auth_data = self.auth_data.as_ref()
            .expect("authenticated at least once");
        let mut headers = auth_data.as_headers();
        headers.insert("Accept".into(), "application/json".into());

        let json_value = perform_json_request(
            &self.client,
            query_uri,
            "POST",
            &headers,
            Some(obj.into()),
        ).await?;
        let aci_objects = json_to_aci_objects(json_value)
            .map_err(|aoe| ApicCommError::InvalidAciObject(aoe))?;
        Ok(aci_objects)
    }

    /// Deletes the object with the given Distinguished Name from the fabric.
    pub async fn delete_object(
        &self,
        dn: &str,
    ) -> Result<(), ApicCommError> {
        let mut query_uri = self.base_uri.clone();

        {
            let mut segs = query_uri.path_segments_mut()
                .expect("base URI does not have editable path segments");
            segs.push("api");
            segs.push("mo");
            segs.push(&format!("{}.json", dn));
        }

        let auth_data = self.auth_data.as_ref()
            .expect("authenticated at least once");
        let mut headers = auth_data.as_headers();
        headers.insert("Accept".into(), "application/json".into());

        perform_json_request(
            &self.client,
            query_uri,
            "DELETE",
            &headers,
            None,
        ).await?;
        Ok(())
    }
}
