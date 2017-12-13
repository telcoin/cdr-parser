#[macro_use] mod common;

pub mod incoming_gateway;
pub mod moc;
pub mod mtc;
pub mod outgoing_gateway;
pub mod roaming;
pub mod smsmo;
pub mod smsmt;

use asn1::*;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Record {
    IncomingGateway(incoming_gateway::Record),
    MOC(moc::Record),
    MTC(mtc::Record),
    OutgoingGateway(outgoing_gateway::Record),
    Roaming(roaming::Record),
    SMSMO(smsmo::Record),
    SMSMT(smsmt::Record),
}

named!(pub record<Record>,
    alt!(
        map!(tlv!(0xA0 => moc::record), Record::MOC)
    |   map!(tlv!(0xA1 => mtc::record), Record::MTC)
    |   map!(tlv!(0xA2 => roaming::record), Record::Roaming)
    |   map!(tlv!(0xA3 => incoming_gateway::record), Record::IncomingGateway)
    |   map!(tlv!(0xA4 => outgoing_gateway::record), Record::OutgoingGateway)
    |   map!(tlv!(0xA6 => smsmo::record), Record::SMSMO)
    |   map!(tlv!(0xA7 => smsmt::record), Record::SMSMT)
    )
);
