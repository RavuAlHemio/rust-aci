pub mod auth;
pub mod conn;
pub mod error;
pub mod multi_conn;
pub mod path;

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use json::{self, JsonValue};

/// The format of timestamps returned by the APIC API.
pub const ACI_TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.3f%:z";

const DN_KEY: &str = "dn";

/// Represents an error encountered when constructing an ACI object.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AciObjectError {
    /// The "dn" attribute, storing the distinguished name, is missing from the attribute HashMap.
    MissingDistinguishedName,

    /// The returned JSON lacks the `imdata` element at the top level.
    NoImdata,

    /// The JSON value is not an object.
    JsonNotObject,

    /// The JSON object representing the ACI object has more than one entry.
    JsonObjectMultipleEntries,

    /// The JSON object representing the ACI object is missing its `attributes` value.
    JsonMissingAttributes,
}
impl fmt::Display for AciObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            AciObjectError::MissingDistinguishedName
                => write!(f, "missing distinguished name attribute ('dn')"),
            AciObjectError::NoImdata
                => write!(f, "missing top-level 'imdata' element"),
            AciObjectError::JsonNotObject
                => write!(f, "JSON value is not an object"),
            AciObjectError::JsonObjectMultipleEntries
                => write!(f, "JSON object has multiple entries"),
            AciObjectError::JsonMissingAttributes
                => write!(f, "JSON object is missing the attributes object"),
        }
    }
}
impl Error for AciObjectError {
}

/// A Managed Object (MO) within ACI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AciObject {
    class_name: String,
    attributes: HashMap<String, String>,
    children: Vec<AciObject>,
}
impl AciObject {
    /// Creates a new AciObject without verifying whether the attributes HashMap contains an entry
    /// for the Distinguished Name.
    fn new_unchecked(
        class_name: String,
        attributes: HashMap<String, String>,
        children: Vec<AciObject>,
    ) -> AciObject {
        AciObject {
            class_name,
            attributes,
            children,
        }
    }

    /// Attempts to create and return a new AciObject.
    pub fn new(
        class_name: String,
        attributes: HashMap<String, String>,
        children: Vec<AciObject>,
    ) -> Result<AciObject, AciObjectError> {
        if !attributes.contains_key(DN_KEY) {
            Err(AciObjectError::MissingDistinguishedName)
        } else {
            Ok(AciObject::new_unchecked(class_name, attributes, children))
        }
    }

    /// Returns the name of the ACI class of which this AciObject is an instance.
    pub fn class_name(&self) -> &str {
        &self.class_name
    }

    /// Sets the name of the ACI class of which this AciObject is an instance.
    pub fn set_class_name<S: AsRef<str>>(&mut self, class_name: S) {
        self.class_name = class_name.as_ref().into()
    }

    /// Returns the Distinguished Name of this AciObject.
    pub fn dn(&self) -> &str {
        self.attributes.get(DN_KEY)
            .expect("missing Distinguished Name attribute")
    }

    /// Returns a reference to the HashMap of attributes of this AciObject.
    pub fn attributes(&self) -> &HashMap<String, String> {
        &self.attributes
    }

    /// Returns a mutable reference to the HashMap of attributes of this AciObject.
    pub fn attributes_mut(&mut self) -> &mut HashMap<String, String> {
        &mut self.attributes
    }

    /// Returns a reference to the vector of children of this AciObject.
    pub fn children(&self) -> &Vec<AciObject> {
        &self.children
    }

    /// Returns a mutable reference to the vector of children of this AciObject.
    pub fn children_mut(&mut self) -> &mut Vec<AciObject> {
        &mut self.children
    }

    /// Attempts to convert a JSON representation of an ACI object into a AciObject.
    ///
    /// A JSON representation of an ACI object is a JSON object with one entry whose key is the
    /// class name of the object and whose value is a JSON object with one or two entries:
    /// `attributes`, which is a JSON object storing the object's attribute names and values (as
    /// strings); and, optionally, `children`, which is a JSON array containing the object's
    /// children (which are also JSON representations of ACI objects).
    ///
    /// An example of a (childless) representation of a JSON object:
    ///
    /// ```json
    /// {
    ///   "polUni": {
    ///     "attributes": {
    ///       "annotation": "",
    ///       "dn": "uni",
    ///       "nameAlias": ""
    ///     }
    ///   }
    /// }
    /// ```
    pub fn from_json(value: &JsonValue) -> Result<AciObject, AciObjectError> {
        if !value.is_object() {
            return Err(AciObjectError::JsonNotObject);
        }
        if value.entries().count() != 1 {
            return Err(AciObjectError::JsonObjectMultipleEntries);
        }

        for (class_name, keys_values) in value.entries() {
            let mut attribs = HashMap::new();
            let json_attribs = &keys_values["attributes"];
            if json_attribs.is_null() {
                return Err(AciObjectError::JsonMissingAttributes);
            }
            for (key, val) in json_attribs.entries() {
                attribs.insert(
                    String::from(key),
                    String::from(val.as_str().expect("string value")),
                );
            }

            let mut children = Vec::new();
            let json_children = &keys_values["children"];
            for json_child in json_children.members() {
                let child = AciObject::from_json(json_child)?;
                children.push(child);
            }

            return AciObject::new(
                String::from(class_name),
                attribs,
                children,
            );
        }
        panic!("fell out of loop");
    }

    /// Convert this AciObject into its JSON representation.
    ///
    /// For a description of the JSON representation of an AciObject, see `AciObject::from_json`.
    pub fn to_json(&self) -> JsonValue {
        let mut attributes_value = JsonValue::new_object();
        for (k, v) in self.attributes() {
            attributes_value[k] = JsonValue::String(v.clone());
        }

        let mut children_value = JsonValue::new_array();
        for child in self.children() {
            let json_child: JsonValue = child.to_json();
            children_value.push(json_child)
                .expect("failed to push to children");
        }

        let mut props = json::object! {
            attributes: attributes_value,
        };
        if children_value.members().len() > 0 {
            props["children"] = children_value;
        }

        let mut top_object = JsonValue::new_object();
        top_object[self.class_name.clone()] = props;
        top_object
    }
}
