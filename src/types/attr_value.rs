//! Attribute values for Cedar entities.

use cedar_policy::RestrictedExpression;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Attribute values that can be attached to Cedar entities.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq, Hash)]
#[serde(tag = "type", content = "value")]
pub enum AttrValue {
    String(String),
    Bool(bool),
    Long(i64),
    Ip(String),
    #[schema(no_recursion)]
    Set(Vec<AttrValue>), // typically Set<String>; we accept nested AttrValue for convenience
}

impl AttrValue {
    pub fn to_re(&self) -> RestrictedExpression {
        use RestrictedExpression as RE;
        match self {
            AttrValue::String(s) => RE::new_string(s.clone()),
            AttrValue::Bool(b) => RE::new_bool(*b),
            AttrValue::Long(n) => RE::new_long(*n),
            AttrValue::Ip(s) => RE::new_ip(s.clone()), // "192.0.2.1" or "10.0.0.0/8"
            AttrValue::Set(xs) => RE::new_set(xs.iter().map(|x| x.to_re())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attrvalue_set_with_mixed_types() {
        let attr = AttrValue::Set(vec![
            AttrValue::String("foo".to_string()),
            AttrValue::Bool(true),
            AttrValue::Long(42),
        ]);
        let _re = attr.to_re();
    }

    #[test]
    fn test_attrvalue_nested_sets() {
        let attr = AttrValue::Set(vec![
            AttrValue::String("foo".to_string()),
            AttrValue::Set(vec![AttrValue::String("bar".to_string())]),
        ]);
        let _re = attr.to_re();
    }

    #[test]
    fn test_attrvalue_string_to_re() {
        let attr = AttrValue::String("test".to_string());
        let re = attr.to_re();
        assert!(format!("{:?}", re).contains("test"));
    }

    #[test]
    fn test_attrvalue_bool_to_re() {
        let attr_true = AttrValue::Bool(true);
        let attr_false = AttrValue::Bool(false);
        let _re_true = attr_true.to_re();
        let _re_false = attr_false.to_re();
    }

    #[test]
    fn test_attrvalue_long_to_re() {
        let attr_positive = AttrValue::Long(42);
        let attr_negative = AttrValue::Long(-100);
        let attr_zero = AttrValue::Long(0);
        let _re1 = attr_positive.to_re();
        let _re2 = attr_negative.to_re();
        let _re3 = attr_zero.to_re();
    }

    #[test]
    fn test_attrvalue_ip_to_re() {
        let attr_single = AttrValue::Ip("192.0.2.1".to_string());
        let attr_cidr = AttrValue::Ip("10.0.0.0/8".to_string());
        let _re1 = attr_single.to_re();
        let _re2 = attr_cidr.to_re();
    }

    #[test]
    fn test_attrvalue_empty_set() {
        let attr = AttrValue::Set(vec![]);
        let _re = attr.to_re();
    }

    #[test]
    fn test_attrvalue_serialization() {
        let test_cases = vec![
            AttrValue::String("hello".to_string()),
            AttrValue::Bool(true),
            AttrValue::Long(123),
            AttrValue::Ip("10.0.0.1".to_string()),
        ];

        for attr in test_cases {
            let serialized = serde_json::to_value(&attr).unwrap();
            let deserialized: AttrValue = serde_json::from_value(serialized).unwrap();
            assert_eq!(attr, deserialized);
        }
    }

    #[test]
    fn test_attrvalue_set_serialization() {
        let attr = AttrValue::Set(vec![
            AttrValue::String("a".to_string()),
            AttrValue::String("b".to_string()),
        ]);
        let serialized = serde_json::to_value(&attr).unwrap();
        let deserialized: AttrValue = serde_json::from_value(serialized).unwrap();
        assert_eq!(attr, deserialized);
    }

    #[test]
    fn test_attrvalue_clone() {
        let original = AttrValue::String("test".to_string());
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_attrvalue_debug() {
        let attr = AttrValue::String("test".to_string());
        let debug_str = format!("{:?}", attr);
        assert!(debug_str.contains("String"));
    }
}
