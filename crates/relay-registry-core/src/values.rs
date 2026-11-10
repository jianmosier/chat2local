use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(tag = "t", content = "v")]
pub enum V {
    #[default]
    #[serde(rename = "u")]
    Undefined,
    #[serde(rename = "h")]
    Hole,
    #[serde(rename = "null")]
    Null,
    #[serde(rename = "b")]
    Bool(bool),
    #[serde(rename = "n")]
    Number(String),
    #[serde(rename = "s")]
    String(Vec<u16>),
    #[serde(rename = "r")]
    Ref(u32),
    #[serde(rename = "big")]
    BigInt,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: u32,
    pub kind: String,
    pub keys: Vec<Vec<u16>>,
    pub props: Vec<(String, V)>,
    pub items: Vec<V>,
    pub base: Option<u32>,
}
impl V {
    pub fn str(s: &str) -> Self {
        Self::String(s.encode_utf16().collect())
    }
    pub fn num(n: f64) -> Self {
        Self::Number(if n.is_nan() {
            "NaN".into()
        } else if n == 0.0 && n.is_sign_negative() {
            "-0".into()
        } else {
            n.to_string()
        })
    }
    pub fn text(&self) -> String {
        match self {
            Self::String(s) => String::from_utf16_lossy(s),
            _ => String::new(),
        }
    }
    pub fn is(&self, s: &str) -> bool {
        matches!(self,Self::String(v) if s.encode_utf16().eq(v.iter().copied()))
    }
    pub fn number(&self) -> f64 {
        match self {
            Self::Number(s) => s.parse().unwrap_or(f64::NAN),
            Self::Null => 0.0,
            Self::Bool(v) => u8::from(*v) as f64,
            Self::String(s) => {
                let text = String::from_utf16_lossy(s);
                let t = text.trim();
                if t.is_empty() {
                    0.0
                } else {
                    t.parse().unwrap_or(f64::NAN)
                }
            }
            _ => f64::NAN,
        }
    }
    pub fn truthy(&self) -> bool {
        match self {
            Self::Undefined | Self::Hole | Self::Null => false,
            Self::Bool(v) => *v,
            Self::Number(_) => {
                let n = self.number();
                n != 0.0 && !n.is_nan()
            }
            Self::String(v) => !v.is_empty(),
            _ => true,
        }
    }
    pub fn nullish(&self) -> bool {
        matches!(self, Self::Null | Self::Undefined)
    }
    pub fn hex(&self, len: usize) -> bool {
        matches!(self,Self::String(v) if v.len()==len&&v.iter().all(|u|matches!(*u,48..=57|97..=102)))
    }
    pub fn length(&self) -> Option<usize> {
        if let Self::String(v) = self {
            Some(v.len())
        } else {
            None
        }
    }
    pub fn plus_one(&self) -> Self {
        if let Self::String(v) = self {
            let mut s = v.clone();
            s.push(49);
            Self::String(s)
        } else {
            Self::num(self.number() + 1.0)
        }
    }
}
