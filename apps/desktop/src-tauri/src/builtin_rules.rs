pub const CLEANWEB_ADULT_SUPPLEMENT_ID: &str = "default:cleanweb:adult-supplement";
pub const CLEANWEB_ADULT_SUPPLEMENT_URL: &str = "builtin://cleanweb/adult-supplement";
pub const CLEANWEB_ADULT_SUPPLEMENT_TEXT: &str =
    include_str!("../../../../resources/rules/cleanweb-adult-supplement.clash");

pub const CLEANWEB_SECURITY_SUPPLEMENT_ID: &str = "default:cleanweb:security-supplement";
pub const CLEANWEB_SECURITY_SUPPLEMENT_URL: &str = "builtin://cleanweb/security-supplement";
pub const CLEANWEB_SECURITY_SUPPLEMENT_TEXT: &str =
    include_str!("../../../../resources/rules/cleanweb-security-supplement.clash");

pub const CLEANWEB_ENTERTAINMENT_CDN_SUPPLEMENT_ID: &str = "local:cleanweb:entertainment-cdn";
pub const CLEANWEB_ENTERTAINMENT_CDN_SUPPLEMENT_URL: &str = "builtin://cleanweb/entertainment-cdn";
pub const CLEANWEB_ENTERTAINMENT_CDN_SUPPLEMENT_TEXT: &str =
    include_str!("../../../../resources/rules/cleanweb-entertainment-cdn-supplement.clash");

pub const CLEANWEB_STRICT_SUPPLEMENT_ID: &str = "default:cleanweb:strict-supplement";
pub const CLEANWEB_STRICT_SUPPLEMENT_URL: &str = "builtin://cleanweb/strict-supplement";
pub const CLEANWEB_STRICT_SUPPLEMENT_TEXT: &str =
    include_str!("../../../../resources/rules/cleanweb-strict-supplement.clash");

pub fn text_for_url(url: &str) -> Option<&'static str> {
    match url {
        CLEANWEB_ADULT_SUPPLEMENT_URL => Some(CLEANWEB_ADULT_SUPPLEMENT_TEXT),
        CLEANWEB_SECURITY_SUPPLEMENT_URL => Some(CLEANWEB_SECURITY_SUPPLEMENT_TEXT),
        CLEANWEB_ENTERTAINMENT_CDN_SUPPLEMENT_URL => {
            Some(CLEANWEB_ENTERTAINMENT_CDN_SUPPLEMENT_TEXT)
        }
        CLEANWEB_STRICT_SUPPLEMENT_URL => Some(CLEANWEB_STRICT_SUPPLEMENT_TEXT),
        _ => None,
    }
}
