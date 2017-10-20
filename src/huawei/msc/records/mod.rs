#[macro_use] mod common;

pub mod moc;
pub mod mtc;
pub mod smsmo;
pub mod smsmt;

use asn1::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Record {
    MOC(moc::Record),
    MTC(mtc::Record),
    SMSMO(smsmo::Record),
    SMSMT(smsmt::Record),
}

named!(pub record<Record>,
    alt!(
        map!(tlv!(0xA0 => moc::record), Record::MOC)
    |   map!(tlv!(0xA1 => mtc::record), Record::MTC)
    |   map!(tlv!(0xA6 => smsmo::record), Record::SMSMO)
    |   map!(tlv!(0xA7 => smsmt::record), Record::SMSMT)
    )
);
